#include "aes-256_gcm.h"

#include <mbedtls/aes.h>
#include <string.h>

uint32_t g_aes128_block_calls = 0;
uint32_t g_aes256_block_calls = 0;

void aes_gcm_counters_reset(void)
{
    g_aes128_block_calls = 0;
    g_aes256_block_calls = 0;
}

uint32_t aes_128_gcm_get_block_calls(void)
{
    return g_aes128_block_calls;
}

uint32_t aes_256_gcm_get_block_calls(void)
{
    return g_aes256_block_calls;
}

static void inc_be32(uint8_t ctr[16])
{
    for (int i = 15; i >= 12; --i) {
        if (++ctr[i] != 0) {
            break;
        }
    }
}

static int ct_memcmp_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0;
}

static void xor_block(uint8_t out[16], const uint8_t in[16])
{
    for (int i = 0; i < 16; ++i) {
        out[i] ^= in[i];
    }
}

static uint64_t load64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) |
           ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) |
           ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) |
           ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8)  |
           ((uint64_t)in[7]);
}

static void store64_be(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

static void gf_mul_128(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16])
{
    uint64_t Xh = load64_be(X);
    uint64_t Xl = load64_be(X + 8);
    uint64_t Vh = load64_be(Y);
    uint64_t Vl = load64_be(Y + 8);
    uint64_t Zh = 0;
    uint64_t Zl = 0;

    for (int i = 0; i < 128; ++i) {
        int bit;

        if (i < 64) {
            bit = (int)((Xh >> (63 - i)) & 1U);
        } else {
            bit = (int)((Xl >> (63 - (i - 64))) & 1U);
        }

        if (bit) {
            Zh ^= Vh;
            Zl ^= Vl;
        }

        {
            int lsb = (int)(Vl & 1U);
            uint64_t new_vl = (Vl >> 1) | ((Vh & 1U) << 63);
            uint64_t new_vh = (Vh >> 1);

            Vh = new_vh;
            Vl = new_vl;

            if (lsb) {
                Vh ^= 0xE100000000000000ULL;
            }
        }
    }

    store64_be(out, Zh);
    store64_be(out + 8, Zl);
}

static void ghash(const uint8_t H[16],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len,
                  uint8_t out[16])
{
    uint8_t Y[16] = {0};
    uint8_t block[16];
    uint8_t tmp[16];
    size_t off = 0;

    while (off + 16 <= aad_len) {
        memcpy(block, aad + off, 16);
        xor_block(Y, block);
        gf_mul_128(Y, H, tmp);
        memcpy(Y, tmp, 16);
        off += 16;
    }

    if (off < aad_len) {
        size_t rem = aad_len - off;
        memset(block, 0, sizeof(block));
        memcpy(block, aad + off, rem);
        xor_block(Y, block);
        gf_mul_128(Y, H, tmp);
        memcpy(Y, tmp, 16);
    }

    off = 0;
    while (off + 16 <= ct_len) {
        memcpy(block, ct + off, 16);
        xor_block(Y, block);
        gf_mul_128(Y, H, tmp);
        memcpy(Y, tmp, 16);
        off += 16;
    }

    if (off < ct_len) {
        size_t rem = ct_len - off;
        memset(block, 0, sizeof(block));
        memcpy(block, ct + off, rem);
        xor_block(Y, block);
        gf_mul_128(Y, H, tmp);
        memcpy(Y, tmp, 16);
    }

    {
        uint8_t len_block[16];
        uint64_t aad_bits = (uint64_t)aad_len * 8U;
        uint64_t ct_bits = (uint64_t)ct_len * 8U;

        store64_be(len_block, aad_bits);
        store64_be(len_block + 8, ct_bits);
        xor_block(Y, len_block);
        gf_mul_128(Y, H, tmp);
        memcpy(Y, tmp, 16);
    }

    memcpy(out, Y, 16);
}

static void aes_block(mbedtls_aes_context *ctx,
                      unsigned int key_bits,
                      const uint8_t in[16],
                      uint8_t out[16])
{
    if (key_bits == 128U) {
        ++g_aes128_block_calls;
    } else {
        ++g_aes256_block_calls;
    }

    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

static void derive_j0(mbedtls_aes_context *ctx,
                      unsigned int key_bits,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t H[16],
                      uint8_t J0[16])
{
    (void)ctx;
    (void)key_bits;

    if (iv_len == AES_GCM_NONCE_LEN) {
        memset(J0, 0, 16);
        memcpy(J0, iv, AES_GCM_NONCE_LEN);
        J0[15] = 1;
        return;
    }

    ghash(H, NULL, 0, iv, iv_len, J0);
}

static void ctr_crypt(mbedtls_aes_context *ctx,
                      unsigned int key_bits,
                      const uint8_t J0[16],
                      const uint8_t *in, size_t len,
                      uint8_t *out)
{
    uint8_t ctr[16];
    uint8_t stream[16];
    size_t off = 0;

    memcpy(ctr, J0, 16);

    while (off < len) {
        size_t chunk;

        inc_be32(ctr);
        aes_block(ctx, key_bits, ctr, stream);

        chunk = (len - off < 16U) ? (len - off) : 16U;
        for (size_t i = 0; i < chunk; ++i) {
            out[off + i] = (uint8_t)(in[off + i] ^ stream[i]);
        }
        off += chunk;
    }
}

static void gcm_auth_only(const uint8_t *key, unsigned int key_bits,
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct, size_t ct_len,
                          uint8_t tag[16])
{
    mbedtls_aes_context ctx;
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t S[16];
    uint8_t GH[16];

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, key_bits);

    aes_block(&ctx, key_bits, zero, H);
    derive_j0(&ctx, key_bits, iv, iv_len, H, J0);
    ghash(H, aad, aad_len, ct, ct_len, GH);
    aes_block(&ctx, key_bits, J0, S);

    for (int i = 0; i < 16; ++i) {
        tag[i] = (uint8_t)(S[i] ^ GH[i]);
    }

    mbedtls_aes_free(&ctx);
}

static int gcm_verify_only(const uint8_t *key, unsigned int key_bits,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[16])
{
    uint8_t expected[16];

    gcm_auth_only(key, key_bits, iv, iv_len, aad, aad_len, ct, ct_len, expected);
    return ct_memcmp_eq(expected, tag, 16) ? 0 : -1;
}

static void gcm_encrypt_auth(const uint8_t *key, unsigned int key_bits,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t *ct,
                             uint8_t tag[16])
{
    mbedtls_aes_context ctx;
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t S[16];
    uint8_t GH[16];

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, key_bits);

    aes_block(&ctx, key_bits, zero, H);
    derive_j0(&ctx, key_bits, iv, iv_len, H, J0);
    ctr_crypt(&ctx, key_bits, J0, pt, pt_len, ct);
    ghash(H, aad, aad_len, ct, pt_len, GH);
    aes_block(&ctx, key_bits, J0, S);

    for (int i = 0; i < 16; ++i) {
        tag[i] = (uint8_t)(S[i] ^ GH[i]);
    }

    mbedtls_aes_free(&ctx);
}

static int gcm_decrypt_verify(const uint8_t *key, unsigned int key_bits,
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t tag[16],
                              uint8_t *pt)
{
    mbedtls_aes_context ctx;
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t S[16];
    uint8_t GH[16];
    uint8_t expected[16];

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, key_bits);

    aes_block(&ctx, key_bits, zero, H);
    derive_j0(&ctx, key_bits, iv, iv_len, H, J0);
    ghash(H, aad, aad_len, ct, ct_len, GH);
    aes_block(&ctx, key_bits, J0, S);

    for (int i = 0; i < 16; ++i) {
        expected[i] = (uint8_t)(S[i] ^ GH[i]);
    }

    if (!ct_memcmp_eq(expected, tag, 16)) {
        mbedtls_aes_free(&ctx);
        return -1;
    }

    ctr_crypt(&ctx, key_bits, J0, ct, ct_len, pt);
    mbedtls_aes_free(&ctx);
    return 0;
}

static void gcm_ctr_only(const uint8_t *key, unsigned int key_bits,
                         const uint8_t iv[AES_GCM_NONCE_LEN],
                         const uint8_t *in, size_t len,
                         uint8_t *out)
{
    mbedtls_aes_context ctx;
    uint8_t J0[16] = {0};

    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, key_bits);

    memcpy(J0, iv, AES_GCM_NONCE_LEN);
    J0[15] = 1;
    ctr_crypt(&ctx, key_bits, J0, in, len, out);

    mbedtls_aes_free(&ctx);
}

void aes_128_gcm_ctr_crypt(const uint8_t key[AES128_KEY_LEN],
                           const uint8_t iv[AES_GCM_NONCE_LEN],
                           const uint8_t *in, size_t len,
                           uint8_t *out)
{
    gcm_ctr_only(key, 128U, iv, in, len, out);
}

void aes_128_gcm_auth(const uint8_t key[AES128_KEY_LEN],
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t tag[AES_GCM_TAG_LEN])
{
    gcm_auth_only(key, 128U, iv, iv_len, aad, aad_len, ct, ct_len, tag);
}

int aes_128_gcm_verify(const uint8_t key[AES128_KEY_LEN],
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[AES_GCM_TAG_LEN])
{
    return gcm_verify_only(key, 128U, iv, iv_len, aad, aad_len, ct, ct_len, tag);
}

void aes_128_gcm_encrypt_auth(const uint8_t key[AES128_KEY_LEN],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *ct,
                              uint8_t tag[AES_GCM_TAG_LEN])
{
    gcm_encrypt_auth(key, 128U, iv, iv_len, aad, aad_len, pt, pt_len, ct, tag);
}

int aes_128_gcm_decrypt_verify(const uint8_t key[AES128_KEY_LEN],
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[AES_GCM_TAG_LEN],
                               uint8_t *pt)
{
    return gcm_decrypt_verify(key, 128U, iv, iv_len, aad, aad_len, ct, ct_len, tag, pt);
}

void aes_256_gcm_ctr_crypt(const uint8_t key[AES256_KEY_LEN],
                           const uint8_t iv[AES_GCM_NONCE_LEN],
                           const uint8_t *in, size_t len,
                           uint8_t *out)
{
    gcm_ctr_only(key, 256U, iv, in, len, out);
}

void aes_256_gcm_auth(const uint8_t key[AES256_KEY_LEN],
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t tag[AES_GCM_TAG_LEN])
{
    gcm_auth_only(key, 256U, iv, iv_len, aad, aad_len, ct, ct_len, tag);
}

int aes_256_gcm_verify(const uint8_t key[AES256_KEY_LEN],
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[AES_GCM_TAG_LEN])
{
    return gcm_verify_only(key, 256U, iv, iv_len, aad, aad_len, ct, ct_len, tag);
}

void aes_256_gcm_encrypt_auth(const uint8_t key[AES256_KEY_LEN],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *ct,
                              uint8_t tag[AES_GCM_TAG_LEN])
{
    gcm_encrypt_auth(key, 256U, iv, iv_len, aad, aad_len, pt, pt_len, ct, tag);
}

int aes_256_gcm_decrypt_verify(const uint8_t key[AES256_KEY_LEN],
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[AES_GCM_TAG_LEN],
                               uint8_t *pt)
{
    return gcm_decrypt_verify(key, 256U, iv, iv_len, aad, aad_len, ct, ct_len, tag, pt);
}
