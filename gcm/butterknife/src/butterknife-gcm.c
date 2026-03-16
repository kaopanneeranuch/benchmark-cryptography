#include "butterknife-gcm.h"
#include "ghash.h"
#include "butterknife.h"
#include <string.h>

#define BK_NUM_BRANCHES 1

static void inc_be32(uint8_t ctr[16])
{
    for (int i = 15; i >= 12; i--)
        if (++ctr[i]) break;
}

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

/*
 * Build a 32-byte tweakey from a 16-byte GCM key.
 * Butterknife-256 expects TK1 (16 B) || TK2 (16 B).
 * TK1 = zeros (tweak), TK2 = key.
 */
static void build_tweakey(uint8_t tk[32], const uint8_t key[16])
{
    memset(tk, 0, 16);
    memcpy(tk + 16, key, 16);
}

/*
 * Encrypt a single 16-byte block with Butterknife-256 (1 branch).
 */
void butterknife_encrypt_block(const uint8_t key[16],
                               const uint8_t in[16], uint8_t out[16])
{
    uint8_t tk[32];
    build_tweakey(tk, key);
    butterknife_256_encrypt(tk, out, in, BK_NUM_BRANCHES);
}

/*
 * CTR-mode encryption / decryption using Butterknife-256.
 */
void butterknife_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                             const uint8_t *pt, size_t len, uint8_t *ct)
{
    uint8_t tk[32];
    build_tweakey(tk, key);

    /* Precompute round tweakeys (key is fixed for the whole CTR stream) */
    uint32_t rtk[4 * (BUTTERKNIFE_ROUNDS + 1)];
    butterknife_256_precompute_rtk(tk, rtk, BK_NUM_BRANCHES);

    uint8_t ctr[16];
    memset(ctr, 0, 16);
    memcpy(ctr, nonce, 12);
    ctr[15] = 1; /* J0 = nonce || 0x00000001 */

    uint8_t keystream[16];
    size_t off = 0;
    while (off < len) {
        inc_be32(ctr);
        butterknife_256_encrypt_w_rtk(rtk, keystream, ctr, BK_NUM_BRANCHES);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            ct[off + i] = pt[off + i] ^ keystream[i];
        off += chunk;
    }
}

void butterknife_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *pt, size_t len,
                             uint8_t *ct, uint8_t tag[16])
{
    uint8_t tk[32];
    build_tweakey(tk, key);

    /* Precompute round tweakeys once */
    uint32_t rtk[4 * (BUTTERKNIFE_ROUNDS + 1)];
    butterknife_256_precompute_rtk(tk, rtk, BK_NUM_BRANCHES);

    /* H = E_k(0) */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    butterknife_256_encrypt_w_rtk(rtk, H, zero, BK_NUM_BRANCHES);

    /* J0 = nonce || 0x00000001 */
    uint8_t J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, 12);
    J0[15] = 1;

    /* CTR encrypt plaintext starting from inc32(J0) */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0;
    uint8_t keystream[16];
    while (off < len) {
        inc_be32(ctr);
        butterknife_256_encrypt_w_rtk(rtk, keystream, ctr, BK_NUM_BRANCHES);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            ct[off + i] = pt[off + i] ^ keystream[i];
        off += chunk;
    }

    /* GHASH(H, AAD, C) */
    uint8_t S[16];
    ghash(H, aad, aad_len, ct, len, S);

    /* Tag = E_k(J0) XOR GHASH */
    uint8_t EkJ0[16];
    butterknife_256_encrypt_w_rtk(rtk, EkJ0, J0, BK_NUM_BRANCHES);
    for (int i = 0; i < 16; ++i)
        tag[i] = EkJ0[i] ^ S[i];
}

int butterknife_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t len,
                            const uint8_t tag[16], uint8_t *pt)
{
    uint8_t tk[32];
    build_tweakey(tk, key);

    /* Precompute round tweakeys once */
    uint32_t rtk[4 * (BUTTERKNIFE_ROUNDS + 1)];
    butterknife_256_precompute_rtk(tk, rtk, BK_NUM_BRANCHES);

    /* H = E_k(0) */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    butterknife_256_encrypt_w_rtk(rtk, H, zero, BK_NUM_BRANCHES);

    /* J0 = nonce || 0x00000001 */
    uint8_t J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, 12);
    J0[15] = 1;

    /* GHASH(H, AAD, C) */
    uint8_t S[16];
    ghash(H, aad, aad_len, ct, len, S);

    /* Compute expected tag = E_k(J0) XOR GHASH */
    uint8_t EkJ0[16];
    butterknife_256_encrypt_w_rtk(rtk, EkJ0, J0, BK_NUM_BRANCHES);
    uint8_t expected[16];
    for (int i = 0; i < 16; ++i)
        expected[i] = EkJ0[i] ^ S[i];

    /* Constant-time compare */
    if (ct_memcmp(expected, tag, 16) != 0)
        return -1;

    /* CTR decrypt ciphertext starting from inc32(J0) */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0;
    uint8_t keystream[16];
    while (off < len) {
        inc_be32(ctr);
        butterknife_256_encrypt_w_rtk(rtk, keystream, ctr, BK_NUM_BRANCHES);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            pt[off + i] = ct[off + i] ^ keystream[i];
        off += chunk;
    }

    return 0;
}
