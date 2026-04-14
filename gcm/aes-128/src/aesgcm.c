#include "aesgcm.h"
#include "ghash.h"
#include <mbedtls/aes.h>
#include <string.h>

uint32_t g_aes_enc_calls = 0;
void aes_counters_reset(void) { g_aes_enc_calls = 0; }

static void inc_be32(uint8_t ctr[16]) { for (int i = 15; i >= 12; i--) if (++ctr[i]) break; }

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff;
}

/* Encrypt one block using a pre-expanded context */
static void aes_block(mbedtls_aes_context *ctx, const uint8_t in[16], uint8_t out[16])
{
    ++g_aes_enc_calls;
    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

/* Public single-block helper (kept for API compat / bench counter probing) */
void aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    ++g_aes_enc_calls;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&ctx);
}

/* CTR encrypt — key expanded once */
void aes_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                     const uint8_t *pt, size_t len, uint8_t *ct)
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t counter[16] = {0};
    memcpy(counter, nonce, 12);
    counter[15] = 1;
    inc_be32(counter);

    size_t off = 0; uint8_t stream[16];
    while (off < len) {
        aes_block(&ctx, counter, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; i++) ct[off + i] = pt[off + i] ^ stream[i];
        off += chunk; inc_be32(counter);
    }
    mbedtls_aes_free(&ctx);
}

/* Full GCM encrypt — key expanded once for all AES calls */
void aes_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len,
                     uint8_t *ct, uint8_t tag[16])
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t zero[16] = {0}, H[16], J0[16] = {0}, S[16], GH[16];

    aes_block(&ctx, zero, H);

    memcpy(J0, nonce, 12);
    J0[15] = 1;

    /* CTR encrypt */
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_be32(counter);
    size_t off = 0; uint8_t stream[16];
    while (off < len) {
        aes_block(&ctx, counter, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; i++) ct[off + i] = pt[off + i] ^ stream[i];
        off += chunk; inc_be32(counter);
    }

    ghash(H, aad, aad_len, ct, len, GH);
    aes_block(&ctx, J0, S);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(S[i] ^ GH[i]);

    mbedtls_aes_free(&ctx);
}

/* Full GCM decrypt — key expanded once */
int aes_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len,
                    const uint8_t tag[16], uint8_t *pt)
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t zero[16] = {0}, H[16], J0[16] = {0}, S[16], GH[16], expected[16];

    aes_block(&ctx, zero, H);

    memcpy(J0, nonce, 12);
    J0[15] = 1;

    ghash(H, aad, aad_len, ct, len, GH);
    aes_block(&ctx, J0, S);
    for (int i = 0; i < 16; i++) expected[i] = (uint8_t)(S[i] ^ GH[i]);

    if (ct_memcmp(expected, tag, 16) != 0) {
        mbedtls_aes_free(&ctx);
        return -1;
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    inc_be32(counter);
    size_t off = 0; uint8_t stream[16];
    while (off < len) {
        aes_block(&ctx, counter, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; i++) pt[off + i] = ct[off + i] ^ stream[i];
        off += chunk; inc_be32(counter);
    }

    mbedtls_aes_free(&ctx);
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
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t zero[16] = {0}, H[16], J0[16], S[16], GH[16];
    aes_block(&ctx, zero, H);
    gcm_derive_j0(H, iv, iv_len, J0);
    ghash(H, aad, aad_len, ct, len, GH);
    aes_block(&ctx, J0, S);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(S[i] ^ GH[i]);

    mbedtls_aes_free(&ctx);
}

int aes_128_gcm_verify(const uint8_t key[16],
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t len,
                       const uint8_t tag[16])
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t zero[16] = {0}, H[16], J0[16], S[16], GH[16], expected[16];
    aes_block(&ctx, zero, H);
    gcm_derive_j0(H, iv, iv_len, J0);
    ghash(H, aad, aad_len, ct, len, GH);
    aes_block(&ctx, J0, S);
    for (int i = 0; i < 16; i++) expected[i] = (uint8_t)(S[i] ^ GH[i]);

    mbedtls_aes_free(&ctx);
    return ct_memcmp(expected, tag, 16) == 0 ? 0 : -1;
}

void aes_128_gcm_encrypt_auth(const uint8_t key[16],
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *pt, size_t len,
                               uint8_t *ct, uint8_t tag[16])
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t zero[16] = {0}, H[16], J0[16], S[16], GH[16];
    aes_block(&ctx, zero, H);
    gcm_derive_j0(H, iv, iv_len, J0);

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0; uint8_t stream[16];
    while (off < len) {
        inc_be32(ctr);
        aes_block(&ctx, ctr, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i) ct[off + i] = pt[off + i] ^ stream[i];
        off += chunk;
    }

    ghash(H, aad, aad_len, ct, len, GH);
    aes_block(&ctx, J0, S);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(S[i] ^ GH[i]);

    mbedtls_aes_free(&ctx);
}

int aes_128_gcm_decrypt_verify(const uint8_t key[16],
                                const uint8_t *iv, size_t iv_len,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t len,
                                const uint8_t tag[16], uint8_t *pt)
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    uint8_t zero[16] = {0}, H[16], J0[16], S[16], GH[16], expected[16];
    aes_block(&ctx, zero, H);
    gcm_derive_j0(H, iv, iv_len, J0);
    ghash(H, aad, aad_len, ct, len, GH);
    aes_block(&ctx, J0, S);
    for (int i = 0; i < 16; i++) expected[i] = (uint8_t)(S[i] ^ GH[i]);

    if (ct_memcmp(expected, tag, 16) != 0) {
        mbedtls_aes_free(&ctx);
        return -1;
    }

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0; uint8_t stream[16];
    while (off < len) {
        inc_be32(ctr);
        aes_block(&ctx, ctr, stream);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i) pt[off + i] = ct[off + i] ^ stream[i];
        off += chunk;
    }

    mbedtls_aes_free(&ctx);
    return 0;
}
