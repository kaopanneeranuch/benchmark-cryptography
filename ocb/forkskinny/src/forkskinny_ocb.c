#include "forkskinny_ocb.h"
#include "forkskinny_tbc.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════
 *  OCB mode instantiated with SKINNY-128-256 TBC
 *  Reference: https://eprint.iacr.org/2001/026  (OCB)
 *
 *  When using a TBC the offset-doubling mechanism of OCB is
 *  replaced by encoding (domain, counter, nonce) directly
 *  into the tweak.  This yields ΘCB / OCB-TBC.
 *
 *  SKINNY-128-256:
 *    n = 128 (block), k = 128 (key), t = 128 (tweak)
 *    nonce = 96 bits, tag = 128 bits
 *
 *  Tweak layout (128 bits = 16 bytes):
 *    domain(4 bits) || counter(28 bits) || nonce(96 bits)
 *
 *  Domain values:
 *    Encryption / decryption of message blocks:
 *      0x0  Msg full block
 *      0x1  Msg last block, padded
 *
 *    AD hash:
 *      0x2  AD full block
 *      0x3  AD last block, padded
 *
 *    Tag finalization:
 *      0x4  Tag (encrypt checksum)
 *
 *  OCB-TBC Enc(K, N, A, M) → (C, T):
 *    Σ ← 0^n  (checksum = XOR of all full plaintext blocks)
 *    For each full msg block M_i (i = 0, 1, ...):
 *      C_i ← Ẽ_K^{0x0, i, N}(M_i)
 *      Σ ← Σ ⊕ M_i
 *    If last block M* is partial (|M*| < n):
 *      pad M* → M*||10*
 *      Σ ← Σ ⊕ (M*||10*)
 *      Pad ← Ẽ_K^{0x1, m, N}(0^n)    (m = index of last block)
 *      C* ← M* ⊕ Pad[0..|M*|-1]      (truncated)
 *    Auth ← 0^n
 *    For each full AD block A_j:
 *      Auth ← Auth ⊕ Ẽ_K^{0x2, j, N}(A_j)
 *    If last AD block A* is partial:
 *      pad A* → A*||10*
 *      Auth ← Auth ⊕ Ẽ_K^{0x3, a, N}(A*||10*)
 *    T ← Ẽ_K^{0x4, 0, N}(Σ) ⊕ Auth
 *
 *  OCB-TBC Dec(K, N, A, C, T) → M or ⊥:
 *    Σ ← 0^n
 *    For each full ct block C_i:
 *      M_i ← Ẽ_K^{-1, 0x0, i, N}(C_i)    (TBC decrypt)
 *      Σ ← Σ ⊕ M_i
 *    If last block C* is partial:
 *      Pad ← Ẽ_K^{0x1, m, N}(0^n)
 *      M* ← C* ⊕ Pad[0..|C*|-1]
 *      Σ ← Σ ⊕ (M*||10*)
 *    Auth ← hash AD (same as encrypt)
 *    T' ← Ẽ_K^{0x4, 0, N}(Σ) ⊕ Auth
 *    if T' ≠ T: return ⊥
 * ══════════════════════════════════════════════════════════ */

/* ── helpers ─────────────────────────────────────────────── */

static void build_tweak(uint8_t tweak[16], uint8_t domain,
                        uint32_t counter, const uint8_t nonce[OCB_NONCE_LEN])
{
    tweak[0] = (uint8_t)((domain << 4) | ((counter >> 24) & 0x0F));
    tweak[1] = (uint8_t)((counter >> 16) & 0xFF);
    tweak[2] = (uint8_t)((counter >>  8) & 0xFF);
    tweak[3] = (uint8_t)( counter        & 0xFF);
    memcpy(tweak + 4, nonce, OCB_NONCE_LEN);
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

/* ── AD hash: returns Auth ═ ⊕ Ẽ(A_j) ──────────────────── */

static void hash_ad(const ocb_key_t *ks,
                    const uint8_t nonce[OCB_NONCE_LEN],
                    const uint8_t *ad, size_t adlen,
                    uint8_t auth[16])
{
    memset(auth, 0, 16);
    if (adlen == 0) return;

    uint8_t tweak[16], out[16], padded[16];

    size_t full = adlen / 16;
    size_t rem  = adlen % 16;

    for (size_t j = 0; j < full; j++) {
        build_tweak(tweak, 0x2, (uint32_t)j, nonce);
        uint8_t out0[16], out1[16];
        fork_encrypt(ks->key, tweak, ad + j * 16, out0, out1);
        xor_block(out, out0, out1, 16);
        xor_block(auth, auth, out, 16);
    }

    if (rem > 0) {
        pad_block(padded, ad + full * 16, rem);
        build_tweak(tweak, 0x3, (uint32_t)full, nonce);
        uint8_t out0[16], out1[16];
        fork_encrypt(ks->key, tweak, padded, out0, out1);
        xor_block(out, out0, out1, 16);
        xor_block(auth, auth, out, 16);
    }
}

/* ── OCB key setup ──────────────────────────────────────── */

void skinny_ocb_keygen(const uint8_t key[OCB_KEY_LEN],
                       ocb_key_t *ks)
{
    memcpy(ks->key, key, OCB_KEY_LEN);
}

/* ────────────────────────────────────────────────────────
 *  Encrypt: OCB-TBC encrypt message blocks
 * ──────────────────────────────────────────────────────── */
void skinny_ocb_encrypt(const ocb_key_t *ks,
                        const uint8_t nonce[OCB_NONCE_LEN],
                        const uint8_t *msg, size_t mlen,
                        uint8_t *ct)
{
    uint8_t tweak[16], zero[16], pad_ks[16];

    size_t full = mlen / 16;
    size_t rem  = mlen % 16;

    /* full blocks: C_i = Ẽ_K(M_i) */
    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, 0x0, (uint32_t)i, nonce);
        uint8_t c0[16], c1[16];
        fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
        memcpy(ct + i * 16, c0, 16);
    }

    /* partial last block: C* = M* ⊕ Ẽ_K(0^n)[0..|M*|] */
    if (rem > 0) {
        memset(zero, 0, 16);
        build_tweak(tweak, 0x1, (uint32_t)full, nonce);
        uint8_t p0[16], p1[16];
        fork_encrypt(ks->key, tweak, zero, p0, p1);
        xor_block(ct + full * 16, msg + full * 16, p0, rem);
    }
}

/* ────────────────────────────────────────────────────────
 *  Decrypt: OCB-TBC decrypt ciphertext blocks
 * ──────────────────────────────────────────────────────── */
void skinny_ocb_decrypt(const ocb_key_t *ks,
                        const uint8_t nonce[OCB_NONCE_LEN],
                        const uint8_t *ct, size_t clen,
                        uint8_t *msg)
{
    uint8_t tweak[16], zero[16], pad_ks[16];

    size_t full = clen / 16;
    size_t rem  = clen % 16;

    /* full blocks: M_i = Ẽ_K^{-1}(C_i) */
    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, 0x0, (uint32_t)i, nonce);
        uint8_t c1[16];
        fork_decrypt(ks->key, tweak, ct + i * 16, msg + i * 16, c1);
    }

    /* partial last block: M* = C* ⊕ Ẽ_K(0^n)[0..|C*|] */
    if (rem > 0) {
        memset(zero, 0, 16);
        build_tweak(tweak, 0x1, (uint32_t)full, nonce);
        uint8_t p0[16], p1[16];
        fork_encrypt(ks->key, tweak, zero, p0, p1);
        xor_block(msg + full * 16, ct + full * 16, p0, rem);
    }
}

/* ────────────────────────────────────────────────────────
 *  Hash (tag): checksum of plaintext ⊕ AD auth
 *    T = Ẽ_K^{0x4,0,N}(Σ) ⊕ Auth
 *  where Σ = M_0 ⊕ M_1 ⊕ ... (⊕ padded last block)
 * ──────────────────────────────────────────────────────── */
void skinny_ocb_hash(const ocb_key_t *ks,
                     const uint8_t nonce[OCB_NONCE_LEN],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *msg, size_t mlen,
                     uint8_t tag[OCB_TAG_LEN])
{
    uint8_t tweak[16], padded[16];
    uint8_t sigma[16];   /* plaintext checksum */
    uint8_t auth[16];    /* AD hash */
    memset(sigma, 0, 16);

    size_t full = mlen / 16;
    size_t rem  = mlen % 16;

    /* Σ = ⊕ M_i (full blocks) */
    for (size_t i = 0; i < full; i++)
        xor_block(sigma, sigma, msg + i * 16, 16);

    /* partial last block: Σ ⊕= (M*||10*) */
    if (rem > 0) {
        pad_block(padded, msg + full * 16, rem);
        xor_block(sigma, sigma, padded, 16);
    }

     /* T_msg = combined output of ForkSkinny on Σ (use both branches)
         We combine the two branch outputs by XORing them so both
         branches contribute to the final tag. */
     build_tweak(tweak, 0x4, 0, nonce);
     uint8_t t0[16], t1[16];
     fork_encrypt(ks->key, tweak, sigma, t0, t1);
     xor_block(tag, t0, t1, 16);

    /* Auth = hash of AD */
    hash_ad(ks, nonce, ad, adlen, auth);

    /* T = T_msg ⊕ Auth */
    xor_block(tag, tag, auth, 16);
}

/* ────────────────────────────────────────────────────────
 *  Verify: recompute tag, compare.
 * ──────────────────────────────────────────────────────── */
int skinny_ocb_verify(const ocb_key_t *ks,
                      const uint8_t nonce[OCB_NONCE_LEN],
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *msg, size_t mlen,
                      const uint8_t tag[OCB_TAG_LEN])
{
    uint8_t computed[OCB_TAG_LEN];
    skinny_ocb_hash(ks, nonce, ad, adlen, msg, mlen, computed);

    int diff = 0;
    for (int i = 0; i < OCB_TAG_LEN; i++)
        diff |= computed[i] ^ tag[i];
    return (diff == 0) ? 0 : -1;
}

/* ────────────────────────────────────────────────────────
 *  Enc(K, N, A, M) → (C, T)
 *    Single-pass: encrypt blocks + accumulate checksum + AD hash
 * ──────────────────────────────────────────────────────── */
void skinny_ocb_encrypt_auth(const ocb_key_t *ks,
                             const uint8_t nonce[OCB_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[OCB_TAG_LEN])
{
    uint8_t tweak[16], zero[16], pad_ks[16], padded[16];
    uint8_t sigma[16], auth[16];
    memset(sigma, 0, 16);

    size_t full = mlen / 16;
    size_t rem  = mlen % 16;

    /* encrypt full blocks + accumulate checksum */
    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, 0x0, (uint32_t)i, nonce);
        uint8_t c0[16], c1[16];
        fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
        memcpy(ct + i * 16, c0, 16);
        xor_block(sigma, sigma, msg + i * 16, 16);
    }

    /* partial last block */
    if (rem > 0) {
        memset(zero, 0, 16);
        build_tweak(tweak, 0x1, (uint32_t)full, nonce);
        uint8_t p0[16], p1[16];
        fork_encrypt(ks->key, tweak, zero, p0, p1);
        xor_block(ct + full * 16, msg + full * 16, p0, rem);

        pad_block(padded, msg + full * 16, rem);
        xor_block(sigma, sigma, padded, 16);
    }

    /* tag = Ẽ(Σ) ⊕ Auth */
    build_tweak(tweak, 0x4, 0, nonce);
    uint8_t t0b[16], t1b[16];
    fork_encrypt(ks->key, tweak, sigma, t0b, t1b);
    xor_block(tag, t0b, t1b, 16);

    hash_ad(ks, nonce, ad, adlen, auth);
    xor_block(tag, tag, auth, 16);
}

/* ────────────────────────────────────────────────────────
 *  Dec(K, N, A, C, T) → M or ⊥
 * ──────────────────────────────────────────────────────── */
int skinny_ocb_decrypt_verify(const ocb_key_t *ks,
                              const uint8_t nonce[OCB_NONCE_LEN],
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *ct, size_t clen,
                              const uint8_t tag[OCB_TAG_LEN],
                              uint8_t *msg)
{
    uint8_t tweak[16], zero[16], pad_ks[16], padded[16];
    uint8_t sigma[16], auth[16], computed_tag[16];
    memset(sigma, 0, 16);

    size_t full = clen / 16;
    size_t rem  = clen % 16;

    /* decrypt full blocks + accumulate checksum */
    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, 0x0, (uint32_t)i, nonce);
        uint8_t c1[16];
        fork_decrypt(ks->key, tweak, ct + i * 16, msg + i * 16, c1);
        xor_block(sigma, sigma, msg + i * 16, 16);
    }

    /* partial last block */
    if (rem > 0) {
        memset(zero, 0, 16);
        build_tweak(tweak, 0x1, (uint32_t)full, nonce);
        uint8_t pad_ks1[16]
        fork_encrypt(ks->key, pad_ks, pad_ks1, zero);
        xor_block(msg + full * 16, ct + full * 16, pad_ks, rem);

        pad_block(padded, msg + full * 16, rem);
        xor_block(sigma, sigma, padded, 16);
    }

    /* verify tag */
    build_tweak(tweak, 0x4, 0, nonce);
    uint8_t tc0[16], tc1[16];
    fork_encrypt(ks->key, tweak, sigma, tc0, tc1);
    xor_block(computed_tag, tc0, tc1, 16);

    hash_ad(ks, nonce, ad, adlen, auth);
    xor_block(computed_tag, computed_tag, auth, 16);

    int diff = 0;
    for (int i = 0; i < OCB_TAG_LEN; i++)
        diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(msg, 0, clen);
        return -1;
    }
    return 0;
}