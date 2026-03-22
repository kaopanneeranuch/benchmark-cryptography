#include "forkskinny_gcm.h"
#include "ghash.h"
#include "ForkAE/internal-forkskinny.h"
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

/*
 * Helper: build a 32-byte tweakey from a 16-byte GCM key.
 * ForkSkinny-128-256 expects  TK1 (16 B) || TK2 (16 B).
 * We place zeros in TK1 and the GCM key in TK2.
 */
static void build_tweakey(uint8_t tk[32], const uint8_t key[16])
{
    memset(tk, 0, 16);
    memcpy(tk + 16, key, 16);
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

/*
 * Encrypt a single 16-byte block with ForkSkinny-128-256.
 * Uses both forks combined as F_k(X) = LEFT(X) XOR RIGHT(X).
 */
void forkskinny_encrypt_block(const uint8_t key[16],
                              const uint8_t in[16], uint8_t out[16])
{
    uint8_t tk[32];
    build_tweakey(tk, key);
    uint8_t c0[16], c1[16];
    forkskinny_128_256_encrypt(tk, c0, c1, in);
    for (int i = 0; i < 16; ++i)
        out[i] = c0[i] ^ c1[i];
}

/*
 * CTR-mode encryption / decryption using ForkSkinny-128-256.
 */
void forkskinny_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                            const uint8_t *pt, size_t len, uint8_t *ct)
{
    uint8_t tk[32];
    build_tweakey(tk, key);

    uint8_t ctr[16];
    memset(ctr, 0, 16);
    memcpy(ctr, nonce, 12);
    ctr[15] = 1; /* initial counter value J0 */

    uint8_t keystream[16];
    uint8_t c0[16], c1[16];
    size_t off = 0;
    while (off < len) {
        inc_be32(ctr);
        /* Use combined output F_k(ctr) = LEFT(ctr) XOR RIGHT(ctr). */
        forkskinny_128_256_encrypt(tk, c0, c1, ctr);
        for (int i = 0; i < 16; ++i)
            keystream[i] = c0[i] ^ c1[i];
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            ct[off + i] = pt[off + i] ^ keystream[i];
        off += chunk;
    }
}

void forkskinny_gcm_encrypt(const uint8_t key[16],
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t len,
                            uint8_t *ct, uint8_t tag[16])
{
    uint8_t tk[32];
    build_tweakey(tk, key);

    /* H = combined output of both forks on zero block (XOR both branches) */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t h0[16], h1[16];
    forkskinny_128_256_encrypt(tk, h0, h1, zero);
    for (int i = 0; i < 16; ++i) H[i] = h0[i] ^ h1[i];

    /* J0 derivation per GCM: fast path for 96-bit IV, GHASH path otherwise */
    uint8_t J0[16];
    gcm_derive_j0(H, iv, iv_len, J0);

    /* Encrypt plaintext using CTR starting from J0+1 */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0;
    uint8_t keystream[16];
    uint8_t c0[16], c1[16];
    while (off < len) {
        inc_be32(ctr);
        forkskinny_128_256_encrypt(tk, c0, c1, ctr);
        for (int i = 0; i < 16; ++i)
            keystream[i] = c0[i] ^ c1[i];
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            ct[off + i] = pt[off + i] ^ keystream[i];
        off += chunk;
    }

    /* Compute GHASH(H, A, C) */
    uint8_t S[16];
    ghash(H, aad, aad_len, ct, len, S);

    /* Tag = (E_k_left(J0) XOR E_k_right(J0)) XOR S */
    uint8_t EkJ0[16];
    uint8_t e0[16], e1[16];
    forkskinny_128_256_encrypt(tk, e0, e1, J0);
    for (int i = 0; i < 16; ++i) {
        EkJ0[i] = e0[i] ^ e1[i];
        tag[i] = EkJ0[i] ^ S[i];
    }
}

int forkskinny_gcm_decrypt(const uint8_t key[16],
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t len,
                           const uint8_t tag[16], uint8_t *pt)
{
    uint8_t tk[32];
    build_tweakey(tk, key);

    /* H = combined output of both forks on zero block */
    uint8_t zero[16] = {0};
    uint8_t H[16];
    uint8_t h0[16], h1[16];
    forkskinny_128_256_encrypt(tk, h0, h1, zero);
    for (int i = 0; i < 16; ++i) H[i] = h0[i] ^ h1[i];

    /* J0 derivation per GCM: fast path for 96-bit IV, GHASH path otherwise */
    uint8_t J0[16];
    gcm_derive_j0(H, iv, iv_len, J0);

    /* Compute GHASH(H, A, C) */
    uint8_t S[16];
    ghash(H, aad, aad_len, ct, len, S);

    /* Compute expected tag = (E_k_left(J0) XOR E_k_right(J0)) XOR S */
    uint8_t EkJ0[16];
    uint8_t e0[16], e1[16];
    forkskinny_128_256_encrypt(tk, e0, e1, J0);
    uint8_t expected[16];
    for (int i = 0; i < 16; ++i) expected[i] = (e0[i] ^ e1[i]) ^ S[i];

    /* Constant-time compare */
    if (ct_memcmp(expected, tag, 16) != 0)
        return -1;

    /* Decrypt ciphertext using CTR (J0+1 ..) */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0;
    uint8_t keystream[16];
    uint8_t c0[16], c1[16];
    while (off < len) {
        inc_be32(ctr);
        forkskinny_128_256_encrypt(tk, c0, c1, ctr);
        for (int i = 0; i < 16; ++i)
            keystream[i] = c0[i] ^ c1[i];
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            pt[off + i] = ct[off + i] ^ keystream[i];
        off += chunk;
    }

    return 0;
}

/* ----------------- Benchmark helper implementations ----------------- */
void forkskinny_gcm_keygen(const uint8_t key[16])
{
    (void)key; /* no key schedule required for this wrapper */
}

void forkskinny_gcm_compute_H(const uint8_t key[16], uint8_t H[16])
{
    uint8_t tk[32];
    build_tweakey(tk, key);
    uint8_t zero[16] = {0};
    uint8_t h0[16], h1[16];
    forkskinny_128_256_encrypt(tk, h0, h1, zero);
    for (int i = 0; i < 16; ++i) H[i] = h0[i] ^ h1[i];
}

void forkskinny_gcm_compute_EkJ0(const uint8_t key[16], const uint8_t nonce[12], uint8_t EkJ0[16])
{
    uint8_t tk[32];
    build_tweakey(tk, key);
    uint8_t J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, 12);
    J0[15] = 1;
    uint8_t e0[16], e1[16];
    forkskinny_128_256_encrypt(tk, e0, e1, J0);
    for (int i = 0; i < 16; ++i) EkJ0[i] = e0[i] ^ e1[i];
}