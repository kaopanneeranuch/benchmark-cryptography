#include "forkskinny_zafe.h"
#include "forkskinny_tbc.h"
#include <string.h>

/* ── helpers ─────────────────────────────────────────────── */

static void build_tweak(uint8_t tweak[16], uint8_t domain,
                        uint32_t counter, const uint8_t aux[12])
{
    tweak[0] = (uint8_t)((domain << 4) | ((counter >> 24) & 0x0F));
    tweak[1] = (uint8_t)((counter >> 16) & 0xFF);
    tweak[2] = (uint8_t)((counter >>  8) & 0xFF);
    tweak[3] = (uint8_t)( counter        & 0xFF);
    memcpy(tweak + 4, aux, 12);
}

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b,
                      size_t len)
{
    for (size_t i = 0; i < len; i++) dst[i] = a[i] ^ b[i];
}

static void pad_block(uint8_t padded[16], const uint8_t *src, size_t len)
{
    memset(padded, 0, 16);
    memcpy(padded, src, len);
    padded[len] = 0x80;
}

/* ── process AD in hash pass (shared enc/dec) ────────────── */

static void process_ad(const zafe_key_t *ks,
                       const uint8_t nonce[ZAFE_NONCE_LEN],
                       const uint8_t *ad, size_t adlen,
                       int has_msg,
                       uint8_t sigma[16])
{
    if (adlen == 0) return;

    uint8_t tweak[16], c0[16], c1[16], padded[16];
    uint8_t d_full = has_msg ? 0x0 : 0x2;
    uint8_t d_last = has_msg ? 0x1 : 0x3;

    size_t full = adlen / 16;
    size_t rem  = adlen % 16;

    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, d_full, (uint32_t)i, nonce);
        fork_encrypt(ks->key, tweak, ad + i * 16, c0, c1);
        xor_block(sigma, sigma, c1, 16);   /* c1 = right fork for auth */
    }

    if (rem > 0) {
        pad_block(padded, ad + full * 16, rem);
        build_tweak(tweak, d_last, (uint32_t)full, nonce);
        fork_encrypt(ks->key, tweak, padded, c0, c1);
        xor_block(sigma, sigma, c1, 16);
    }
}

/* ── tag finalization: T = c0 of fork(sigma) ────────────── */

static void finalize_tag(const zafe_key_t *ks,
                         const uint8_t nonce[ZAFE_NONCE_LEN],
                         const uint8_t sigma[16],
                         uint8_t tag[ZAFE_TAG_LEN])
{
    uint8_t tweak[16], c1[16];
    build_tweak(tweak, 0x8, 0, nonce);
    fork_encrypt(ks->key, tweak, sigma, tag, c1);
    /* tag = c0; c1 discarded */
}

/* ── ZAFE key setup ─────────────────────────────────────── */

void forkskinny_zafe_keygen(const uint8_t key[ZAFE_KEY_LEN],
                            zafe_key_t *ks)
{
    memcpy(ks->key, key, ZAFE_KEY_LEN);
}

/* ────────────────────────────────────────────────────────
 *  Hash pass: PMAC over (AD, M) using nonce tweak → tag T
 *  Uses c1 (right fork) for accumulation.
 * ──────────────────────────────────────────────────────── */
void forkskinny_zafe_hash(const zafe_key_t *ks,
                          const uint8_t nonce[ZAFE_NONCE_LEN],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[ZAFE_TAG_LEN])
{
    uint8_t tweak[16], c0[16], c1[16], padded[16];
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    int has_ad  = (adlen > 0);
    int has_msg = (mlen  > 0);

    /* AD blocks */
    process_ad(ks, nonce, ad, adlen, has_msg, sigma);

    /* Message blocks — c1 accumulates into sigma */
    if (has_msg) {
        uint8_t d_full = has_ad ? 0x4 : 0x6;
        uint8_t d_last = has_ad ? 0x5 : 0x7;

        size_t full = mlen / 16;
        size_t rem  = mlen % 16;

        for (size_t i = 0; i < full; i++) {
            build_tweak(tweak, d_full, (uint32_t)i, nonce);
            fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
            xor_block(sigma, sigma, c1, 16);  /* c1 = right fork */
        }

        if (rem > 0) {
            pad_block(padded, msg + full * 16, rem);
            build_tweak(tweak, d_last, (uint32_t)full, nonce);
            fork_encrypt(ks->key, tweak, padded, c0, c1);
            xor_block(sigma, sigma, c1, 16);
        }
    }

    finalize_tag(ks, nonce, sigma, tag);
}

/* ────────────────────────────────────────────────────────
 *  CTR encrypt pass: keystream from fork(0^n) using tag tweak.
 *  Uses c0 (left fork) as keystream.
 * ──────────────────────────────────────────────────────── */
void forkskinny_zafe_encrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct)
{
    uint8_t tweak[16], c0[16], c1[16];
    uint8_t zero[16];
    uint8_t tag12[12];
    memset(zero, 0, 16);
    memcpy(tag12, tag, 12);   /* first 12 bytes of tag as aux */

    size_t full = mlen / 16;
    size_t rem  = mlen % 16;

    for (size_t i = 0; i < full; i++) {
        /* counter starts at 1 per paper */
        build_tweak(tweak, 0xC, (uint32_t)(i + 1), tag12);
        fork_encrypt(ks->key, tweak, zero, c0, c1);
        xor_block(ct + i * 16, msg + i * 16, c0, 16);  /* C_i = M_i ⊕ c0 */
    }

    if (rem > 0) {
        build_tweak(tweak, 0xD, (uint32_t)(full + 1), tag12);
        fork_encrypt(ks->key, tweak, zero, c0, c1);
        xor_block(ct + full * 16, msg + full * 16, c0, rem);
    }
}

/* ────────────────────────────────────────────────────────
 *  CTR decrypt pass: symmetric to encrypt (CTR is invertible).
 * ──────────────────────────────────────────────────────── */
void forkskinny_zafe_decrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg)
{
    /* CTR mode is symmetric */
    forkskinny_zafe_encrypt(ks, tag, ct, clen, msg);
}

/* ────────────────────────────────────────────────────────
 *  Verify: recompute tag from plaintext, compare.
 * ──────────────────────────────────────────────────────── */
int forkskinny_zafe_verify(const zafe_key_t *ks,
                           const uint8_t nonce[ZAFE_NONCE_LEN],
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[ZAFE_TAG_LEN])
{
    uint8_t computed[ZAFE_TAG_LEN];
    forkskinny_zafe_hash(ks, nonce, ad, adlen, msg, mlen, computed);

    int diff = 0;
    for (int i = 0; i < ZAFE_TAG_LEN; i++)
        diff |= computed[i] ^ tag[i];
    return (diff == 0) ? 0 : -1;
}

/* ────────────────────────────────────────────────────────
 *  Enc(K, N, A, M) → (C, T)
 *    Pass 1: hash(K, N, A, M) → T
 *    Pass 2: ctr_enc(K, T, M) → C
 * ──────────────────────────────────────────────────────── */
void forkskinny_zafe_encrypt_auth(const zafe_key_t *ks,
                                  const uint8_t nonce[ZAFE_NONCE_LEN],
                                  const uint8_t *ad, size_t adlen,
                                  const uint8_t *msg, size_t mlen,
                                  uint8_t *ct,
                                  uint8_t tag[ZAFE_TAG_LEN])
{
    forkskinny_zafe_hash(ks, nonce, ad, adlen, msg, mlen, tag);
    forkskinny_zafe_encrypt(ks, tag, msg, mlen, ct);
}

/* ────────────────────────────────────────────────────────
 *  Dec(K, N, A, C, T) → M or ⊥
 *    Pass 1: ctr_dec(K, T, C) → M
 *    Pass 2: verify hash(K, N, A, M) == T
 * ──────────────────────────────────────────────────────── */
int forkskinny_zafe_decrypt_verify(const zafe_key_t *ks,
                                   const uint8_t nonce[ZAFE_NONCE_LEN],
                                   const uint8_t *ad, size_t adlen,
                                   const uint8_t *ct, size_t clen,
                                   const uint8_t tag[ZAFE_TAG_LEN],
                                   uint8_t *msg)
{
    forkskinny_zafe_decrypt(ks, tag, ct, clen, msg);

    uint8_t computed[ZAFE_TAG_LEN];
    forkskinny_zafe_hash(ks, nonce, ad, adlen, msg, clen, computed);

    int diff = 0;
    for (int i = 0; i < ZAFE_TAG_LEN; i++)
        diff |= computed[i] ^ tag[i];

    if (diff != 0) {
        memset(msg, 0, clen);   /* wipe plaintext on failure */
        return -1;
    }
    return 0;
}