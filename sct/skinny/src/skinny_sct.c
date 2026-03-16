#include "skinny_sct.h"
#include "skinny_tbc.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════
 *  SCT  –  Synthetic Counter in Tweak
 *  Reference: https://eprint.iacr.org/2015/1049  §4
 *
 *  Instantiation: SKINNY-128-128
 *    n = 128 (block), k = 128 (key), t = 128 (tweak)
 *    nonce = 96 bits, tag = 128 bits
 *
 *  Tweak layout (128 bits = 16 bytes):
 *    domain(4 bits) || counter(28 bits) || nonce_or_tag(96 bits)
 *
 *  Domain separation (paper §4):
 *    Hash pass (PMAC over AD then M, nonce-based tweak):
 *      0x0  AD full block          (message present)
 *      0x1  AD last block, padded  (message present)
 *      0x2  AD full block          (message empty)
 *      0x3  AD last block, padded  (message empty)
 *      0x4  Msg full block         (AD present)
 *      0x5  Msg last block, padded (AD present)
 *      0x6  Msg full block         (AD empty)
 *      0x7  Msg last block, padded (AD empty)
 *      0x8  Tag finalization
 *
 *    CTR pass (tag-based tweak, encrypt):
 *      0xC  CTR full block
 *      0xD  CTR last block (partial)
 *
 *  Algorithm (Enc):
 *    Pass 1 — PMAC hash:
 *      σ ← 0^n
 *      For each AD block A_i:
 *        σ ← σ ⊕ Ẽ_K^{d_a, i, N}(A_i)
 *      For each msg block M_i:
 *        σ ← σ ⊕ Ẽ_K^{d_m, i, N}(M_i)
 *      T ← Ẽ_K^{0x8, 0, N}(σ)
 *
 *    Pass 2 — CTR encrypt:
 *      For each msg block M_i:
 *        S_i ← Ẽ_K^{0xC, i+1, T[0..11]}(0^n)
 *        C_i ← M_i ⊕ S_i
 *
 *  Key difference from ZAFE:
 *    SKINNY is a normal TBC (one output), not a forkcipher.
 *    Hash uses the single TBC output for PMAC accumulation.
 *    CTR uses the single TBC output as keystream.
 * ══════════════════════════════════════════════════════════ */

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

/* ── process AD blocks in hash pass ──────────────────────── */

static void process_ad(const sct_key_t *ks,
                       const uint8_t nonce[SCT_NONCE_LEN],
                       const uint8_t *ad, size_t adlen,
                       int has_msg,
                       uint8_t sigma[16])
{
    if (adlen == 0) return;

    uint8_t tweak[16], out[16], padded[16];
    uint8_t d_full = has_msg ? 0x0 : 0x2;
    uint8_t d_last = has_msg ? 0x1 : 0x3;

    size_t full = adlen / 16;
    size_t rem  = adlen % 16;

    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, d_full, (uint32_t)i, nonce);
        skinny_encrypt(ks->key, tweak, ad + i * 16, out);
        xor_block(sigma, sigma, out, 16);
    }

    if (rem > 0) {
        pad_block(padded, ad + full * 16, rem);
        build_tweak(tweak, d_last, (uint32_t)full, nonce);
        skinny_encrypt(ks->key, tweak, padded, out);
        xor_block(sigma, sigma, out, 16);
    }
}

/* ── tag finalization ────────────────────────────────────── */

static void finalize_tag(const sct_key_t *ks,
                         const uint8_t nonce[SCT_NONCE_LEN],
                         const uint8_t sigma[16],
                         uint8_t tag[SCT_TAG_LEN])
{
    uint8_t tweak[16];
    build_tweak(tweak, 0x8, 0, nonce);
    skinny_encrypt(ks->key, tweak, sigma, tag);
}

/* ── SCT key setup ──────────────────────────────────────── */

void skinny_sct_keygen(const uint8_t key[SCT_KEY_LEN],
                       sct_key_t *ks)
{
    memcpy(ks->key, key, SCT_KEY_LEN);
}

/* ────────────────────────────────────────────────────────
 *  Hash pass: PMAC over (AD, M) using nonce tweak → tag T
 * ──────────────────────────────────────────────────────── */
void skinny_sct_hash(const sct_key_t *ks,
                     const uint8_t nonce[SCT_NONCE_LEN],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *msg, size_t mlen,
                     uint8_t tag[SCT_TAG_LEN])
{
    uint8_t tweak[16], out[16], padded[16];
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    int has_ad  = (adlen > 0);
    int has_msg = (mlen  > 0);

    /* AD blocks */
    process_ad(ks, nonce, ad, adlen, has_msg, sigma);

    /* Message blocks */
    if (has_msg) {
        uint8_t d_full = has_ad ? 0x4 : 0x6;
        uint8_t d_last = has_ad ? 0x5 : 0x7;

        size_t full = mlen / 16;
        size_t rem  = mlen % 16;

        for (size_t i = 0; i < full; i++) {
            build_tweak(tweak, d_full, (uint32_t)i, nonce);
            skinny_encrypt(ks->key, tweak, msg + i * 16, out);
            xor_block(sigma, sigma, out, 16);
        }

        if (rem > 0) {
            pad_block(padded, msg + full * 16, rem);
            build_tweak(tweak, d_last, (uint32_t)full, nonce);
            skinny_encrypt(ks->key, tweak, padded, out);
            xor_block(sigma, sigma, out, 16);
        }
    }

    finalize_tag(ks, nonce, sigma, tag);
}

/* ────────────────────────────────────────────────────────
 *  CTR encrypt pass: keystream from Ẽ_K(0^n) with tag tweak.
 * ──────────────────────────────────────────────────────── */
void skinny_sct_encrypt(const sct_key_t *ks,
                        const uint8_t tag[SCT_TAG_LEN],
                        const uint8_t *msg, size_t mlen,
                        uint8_t *ct)
{
    uint8_t tweak[16], out[16];
    uint8_t zero[16];
    uint8_t tag12[12];
    memset(zero, 0, 16);
    memcpy(tag12, tag, 12);

    size_t full = mlen / 16;
    size_t rem  = mlen % 16;

    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, 0xC, (uint32_t)(i + 1), tag12);
        skinny_encrypt(ks->key, tweak, zero, out);
        xor_block(ct + i * 16, msg + i * 16, out, 16);
    }

    if (rem > 0) {
        build_tweak(tweak, 0xD, (uint32_t)(full + 1), tag12);
        skinny_encrypt(ks->key, tweak, zero, out);
        xor_block(ct + full * 16, msg + full * 16, out, rem);
    }
}

/* ────────────────────────────────────────────────────────
 *  CTR decrypt pass: symmetric to encrypt.
 * ──────────────────────────────────────────────────────── */
void skinny_sct_decrypt(const sct_key_t *ks,
                        const uint8_t tag[SCT_TAG_LEN],
                        const uint8_t *ct, size_t clen,
                        uint8_t *msg)
{
    skinny_sct_encrypt(ks, tag, ct, clen, msg);
}

/* ────────────────────────────────────────────────────────
 *  Verify: recompute tag from plaintext, compare.
 * ──────────────────────────────────────────────────────── */
int skinny_sct_verify(const sct_key_t *ks,
                      const uint8_t nonce[SCT_NONCE_LEN],
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *msg, size_t mlen,
                      const uint8_t tag[SCT_TAG_LEN])
{
    uint8_t computed[SCT_TAG_LEN];
    skinny_sct_hash(ks, nonce, ad, adlen, msg, mlen, computed);

    int diff = 0;
    for (int i = 0; i < SCT_TAG_LEN; i++)
        diff |= computed[i] ^ tag[i];
    return (diff == 0) ? 0 : -1;
}

/* ────────────────────────────────────────────────────────
 *  Enc(K, N, A, M) → (C, T)
 *    Pass 1: hash(K, N, A, M) → T
 *    Pass 2: ctr_enc(K, T, M) → C
 * ──────────────────────────────────────────────────────── */
void skinny_sct_encrypt_auth(const sct_key_t *ks,
                             const uint8_t nonce[SCT_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[SCT_TAG_LEN])
{
    skinny_sct_hash(ks, nonce, ad, adlen, msg, mlen, tag);
    skinny_sct_encrypt(ks, tag, msg, mlen, ct);
}

/* ────────────────────────────────────────────────────────
 *  Dec(K, N, A, C, T) → M or ⊥
 *    Pass 1: ctr_dec(K, T, C) → M
 *    Pass 2: verify hash(K, N, A, M) == T
 * ──────────────────────────────────────────────────────── */
int skinny_sct_decrypt_verify(const sct_key_t *ks,
                              const uint8_t nonce[SCT_NONCE_LEN],
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *ct, size_t clen,
                              const uint8_t tag[SCT_TAG_LEN],
                              uint8_t *msg)
{
    skinny_sct_decrypt(ks, tag, ct, clen, msg);

    uint8_t computed[SCT_TAG_LEN];
    skinny_sct_hash(ks, nonce, ad, adlen, msg, clen, computed);

    int diff = 0;
    for (int i = 0; i < SCT_TAG_LEN; i++)
        diff |= computed[i] ^ tag[i];

    if (diff != 0) {
        memset(msg, 0, clen);
        return -1;
    }
    return 0;
}