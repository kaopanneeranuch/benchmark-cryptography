#include "aesgcm.h"
#include "ghash.h"
#include <mbedtls/aes.h>
#include <string.h>


static void inc_be32(uint8_t ctr[16]) { for (int i = 15; i >= 12; i--) if (++ctr[i]) break; }

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

void aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    mbedtls_aes_context ctx; mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&ctx);
}

void aes_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *pt, size_t len, uint8_t *ct)
{
    uint8_t counter[16] = {0};
    memcpy(counter, nonce, 12);
    counter[15] = 1; /* J0 = nonce || 0x00000001 for 96-bit nonce */
    inc_be32(counter); /* GCTR payload starts at inc32(J0) */

    size_t off = 0; uint8_t stream[16], block[16];
    while (off < len) {
        aes_encrypt_block(key, counter, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        memcpy(block, pt + off, chunk);
        for (size_t i = 0; i < chunk; i++) ct[off + i] = block[i] ^ stream[i];
        off += chunk; inc_be32(counter);
    }
}

void aes_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t len,
                       uint8_t *ct, uint8_t tag[16])
{
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16] = {0};
    uint8_t S[16];
    uint8_t GH[16];

    aes_encrypt_block(key, zero, H);

    memcpy(J0, nonce, 12);
    J0[15] = 1; /* 96-bit nonce fast path */

    aes_ctr_encrypt(key, nonce, pt, len, ct);

    ghash(H, aad, aad_len, ct, len, GH);
    aes_encrypt_block(key, J0, S);

    for (int i = 0; i < 16; i++) {
        tag[i] = (uint8_t)(S[i] ^ GH[i]);
    }
}

int aes_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t len,
                      const uint8_t tag[16], uint8_t *pt)
{
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16] = {0};
    uint8_t S[16];
    uint8_t GH[16];
    uint8_t expected[16];

    aes_encrypt_block(key, zero, H);

    memcpy(J0, nonce, 12);
    J0[15] = 1;

    ghash(H, aad, aad_len, ct, len, GH);
    aes_encrypt_block(key, J0, S);

    for (int i = 0; i < 16; i++) {
        expected[i] = (uint8_t)(S[i] ^ GH[i]);
    }

    if (ct_memcmp(expected, tag, 16) != 0) {
        return -1;
    }

    aes_ctr_encrypt(key, nonce, ct, len, pt);
    return 0;
}

static void gcm_derive_j0(const uint8_t H[16], const uint8_t *iv, size_t iv_len, uint8_t J0[16])
{
    if (iv_len == 12) {
        memset(J0, 0, 16);
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        ghash(H, NULL, 0, iv, iv_len, J0);
    }
}

void aes_128_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *pt, size_t len, uint8_t *ct)
{
    aes_ctr_encrypt(key, nonce, pt, len, ct);
}

void aes_128_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *ct, size_t len, uint8_t *pt)
{
    aes_ctr_encrypt(key, nonce, ct, len, pt);
}

void aes_128_gcm_auth(const uint8_t key[16],
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t len,
                      uint8_t tag[16])
{
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t S[16];
    uint8_t GH[16];

    aes_encrypt_block(key, zero, H);
    gcm_derive_j0(H, iv, iv_len, J0);

    ghash(H, aad, aad_len, ct, len, GH);
    aes_encrypt_block(key, J0, S);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(S[i] ^ GH[i]);
}

int aes_128_gcm_verify(const uint8_t key[16],
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t len,
                       const uint8_t tag[16])
{
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t S[16];
    uint8_t GH[16];
    uint8_t expected[16];

    aes_encrypt_block(key, zero, H);
    gcm_derive_j0(H, iv, iv_len, J0);

    ghash(H, aad, aad_len, ct, len, GH);
    aes_encrypt_block(key, J0, S);

    for (int i = 0; i < 16; i++) expected[i] = (uint8_t)(S[i] ^ GH[i]);
    return ct_memcmp(expected, tag, 16) == 0 ? 0 : -1;
}

void aes_128_gcm_encrypt_auth(const uint8_t key[16],
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *pt, size_t len,
                             uint8_t *ct, uint8_t tag[16])
{
    /* Encrypt */
    if (iv_len == 12) {
        aes_ctr_encrypt(key, iv, pt, len, ct);
    } else {
        uint8_t J0[16];
        uint8_t zero[16] = {0};
        uint8_t H[16];
        aes_encrypt_block(key, zero, H);
        gcm_derive_j0(H, iv, iv_len, J0);

        uint8_t ctr[16];
        memcpy(ctr, J0, 16);
        size_t off = 0; uint8_t stream[16];
        while (off < len) {
            inc_be32(ctr);
            aes_encrypt_block(key, ctr, stream);
            size_t chunk = (len - off) < 16 ? (len - off) : 16;
            for (size_t i = 0; i < chunk; ++i) ct[off + i] = pt[off + i] ^ stream[i];
            off += chunk;
        }
    }

    /* Auth (compute tag) */
    aes_128_gcm_auth(key, iv, iv_len, aad, aad_len, ct, len, tag);
}

int aes_128_gcm_decrypt_verify(const uint8_t key[16],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ct, size_t len,
                              const uint8_t tag[16], uint8_t *pt)
{
    if (aes_128_gcm_verify(key, iv, iv_len, aad, aad_len, ct, len, tag) != 0)
        return -1;

    if (iv_len == 12) {
        aes_ctr_encrypt(key, iv, ct, len, pt);
    } else {
        uint8_t J0[16];
        uint8_t zero[16] = {0};
        uint8_t H[16];
        aes_encrypt_block(key, zero, H);
        gcm_derive_j0(H, iv, iv_len, J0);

        uint8_t ctr[16];
        memcpy(ctr, J0, 16);
        size_t off = 0; uint8_t stream[16];
        while (off < len) {
            inc_be32(ctr);
            aes_encrypt_block(key, ctr, stream);
            size_t chunk = (len - off) < 16 ? (len - off) : 16;
            for (size_t i = 0; i < chunk; ++i) pt[off + i] = ct[off + i] ^ stream[i];
            off += chunk;
        }
    }
    return 0;
}