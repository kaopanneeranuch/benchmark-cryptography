#include "aes_gcm.h"
#include "ghash.h"
#include <mbedtls/aes.h>
#include <string.h>

/* ── file-scope AES context – avoids ~280 B stack per call ─── */
static mbedtls_aes_context g_ctx;
static uint8_t             g_cached_key[16];
static int                 g_ctx_ready;

static void ensure_key(const uint8_t key[16])
{
    if (!g_ctx_ready || memcmp(g_cached_key, key, 16) != 0) {
        mbedtls_aes_init(&g_ctx);
        mbedtls_aes_setkey_enc(&g_ctx, key, 128);
        memcpy(g_cached_key, key, 16);
        g_ctx_ready = 1;
    }
}

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
    ensure_key(key);
    mbedtls_aes_crypt_ecb(&g_ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

void aes_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *pt, size_t len, uint8_t *ct)
{
    static uint8_t counter[16];
    static uint8_t stream[16], block[16];
    memset(counter, 0, 16);
    memcpy(counter, nonce, 12);
    counter[15] = 1; /* J0 = nonce || 0x00000001 for 96-bit nonce */
    inc_be32(counter); /* GCTR payload starts at inc32(J0) */

    ensure_key(key);

    size_t off = 0;
    while (off < len) {
        mbedtls_aes_crypt_ecb(&g_ctx, MBEDTLS_AES_ENCRYPT, counter, stream);
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
    static uint8_t zero[16];
    static uint8_t H[16];
    static uint8_t J0[16];
    static uint8_t S[16];
    static uint8_t GH[16];
    memset(zero, 0, 16);
    memset(J0, 0, 16);

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
    static uint8_t zero[16];
    static uint8_t H[16];
    static uint8_t J0[16];
    static uint8_t S[16];
    static uint8_t GH[16];
    static uint8_t expected[16];
    memset(zero, 0, 16);
    memset(J0, 0, 16);

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