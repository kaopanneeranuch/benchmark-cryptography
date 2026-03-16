#include "forkskinny_safe.h"
#include "forkskinny_tbc.h"
#include <string.h>

/* ── helpers ─────────────────────────────────────────────── */

static void build_tweak(uint8_t tweak[16], uint8_t domain,
                        uint32_t counter, const uint8_t nonce[SAFE_NONCE_LEN])
{
    tweak[0] = (uint8_t)((domain << 4) | ((counter >> 24) & 0x0F));
    tweak[1] = (uint8_t)((counter >> 16) & 0xFF);
    tweak[2] = (uint8_t)((counter >>  8) & 0xFF);
    tweak[3] = (uint8_t)( counter        & 0xFF);
    memcpy(tweak + 4, nonce, SAFE_NONCE_LEN);
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

/* ── process AD blocks (shared by enc and dec) ──────────── */

static void process_ad(const safe_key_t *ks,
                       const uint8_t nonce[SAFE_NONCE_LEN],
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
        xor_block(sigma, sigma, c1, 16);
    }

    if (rem > 0) {
        pad_block(padded, ad + full * 16, rem);
        build_tweak(tweak, d_last, (uint32_t)full, nonce);
        fork_encrypt(ks->key, tweak, padded, c0, c1);
        xor_block(sigma, sigma, c1, 16);
    }
}

/* ── tag finalization: T = c0 of fork(sigma) ────────────── */

static void finalize_tag(const safe_key_t *ks,
                         const uint8_t nonce[SAFE_NONCE_LEN],
                         const uint8_t sigma[16],
                         uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t tweak[16], c1[16];
    build_tweak(tweak, 0x8, 0, nonce);
    fork_encrypt(ks->key, tweak, sigma, tag, c1);
    /* tag = c0; c1 discarded */
}

/* ── SAFE API ───────────────────────────────────────────── */

void forkskinny_safe_keygen(const uint8_t key[SAFE_KEY_LEN],
                            safe_key_t *ks)
{
    memcpy(ks->key, key, SAFE_KEY_LEN);
}

void forkskinny_safe_encrypt_auth(const safe_key_t *ks,
                                  const uint8_t nonce[SAFE_NONCE_LEN],
                                  const uint8_t *ad, size_t adlen,
                                  const uint8_t *msg, size_t mlen,
                                  uint8_t *ct,
                                  uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t tweak[16], c0[16], c1[16], padded[16];
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    int has_ad  = (adlen > 0);
    int has_msg = (mlen  > 0);

    /* AD */
    process_ad(ks, nonce, ad, adlen, has_msg, sigma);

    /* Message: fork each block, c0 = ciphertext, c1 = auth */
    if (has_msg) {
        uint8_t d_full = has_ad ? 0x4 : 0x6;
        uint8_t d_last = has_ad ? 0x5 : 0x7;

        size_t full = mlen / 16;
        size_t rem  = mlen % 16;

        for (size_t i = 0; i < full; i++) {
            build_tweak(tweak, d_full, (uint32_t)i, nonce);
            fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
            memcpy(ct + i * 16, c0, 16);
            xor_block(sigma, sigma, c1, 16);
        }

        if (rem > 0) {
            pad_block(padded, msg + full * 16, rem);
            build_tweak(tweak, d_last, (uint32_t)full, nonce);
            uint8_t zero_padded[16], ks_c0[16], ks_c1[16];
            memset(zero_padded, 0, 16);
            zero_padded[0] = 0x80;
            fork_encrypt(ks->key, tweak, zero_padded, ks_c0, ks_c1);
            for (size_t j = 0; j < rem; j++)
                ct[full * 16 + j] = msg[full * 16 + j] ^ ks_c0[j];
            fork_encrypt(ks->key, tweak, padded, c0, c1);
            xor_block(sigma, sigma, c1, 16);
        }
    }

    /* Tag */
    finalize_tag(ks, nonce, sigma, tag);
}

int forkskinny_safe_decrypt_verify(const safe_key_t *ks,
                                   const uint8_t nonce[SAFE_NONCE_LEN],
                                   const uint8_t *ad, size_t adlen,
                                   const uint8_t *ct, size_t clen,
                                   const uint8_t tag[SAFE_TAG_LEN],
                                   uint8_t *msg)
{
    uint8_t tweak[16], c0[16], c1[16], padded[16];
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    int has_ad  = (adlen > 0);
    int has_msg = (clen  > 0);

    /* AD (identical to encrypt) */
    process_ad(ks, nonce, ad, adlen, has_msg, sigma);

    /* Ciphertext: invert c0 to recover M, re-fork M for c1 */
    if (has_msg) {
        uint8_t d_full = has_ad ? 0x4 : 0x6;
        uint8_t d_last = has_ad ? 0x5 : 0x7;

        size_t full = clen / 16;
        size_t rem  = clen % 16;

        for (size_t i = 0; i < full; i++) {
            build_tweak(tweak, d_full, (uint32_t)i, nonce);
            /* invert c0 branch to recover plaintext */
            fork_decrypt(ks->key, tweak, ct + i * 16, msg + i * 16, c1);
            /* re-fork recovered plaintext to get c1 for auth */
            fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
            xor_block(sigma, sigma, c1, 16);
        }

        if (rem > 0) {
            build_tweak(tweak, d_last, (uint32_t)full, nonce);
            uint8_t zero_padded[16], ks_c0[16], ks_c1[16];
            memset(zero_padded, 0, 16);
            zero_padded[0] = 0x80;
            fork_encrypt(ks->key, tweak, zero_padded, ks_c0, ks_c1);
            for (size_t j = 0; j < rem; j++)
                msg[full * 16 + j] = ct[full * 16 + j] ^ ks_c0[j];
            /* re-fork with proper padding for auth */
            pad_block(padded, msg + full * 16, rem);
            fork_encrypt(ks->key, tweak, padded, c0, c1);
            xor_block(sigma, sigma, c1, 16);
        }
    }

    /* Tag verification */
    uint8_t computed_tag[SAFE_TAG_LEN];
    finalize_tag(ks, nonce, sigma, computed_tag);

    /* constant-time compare */
    int diff = 0;
    for (int i = 0; i < SAFE_TAG_LEN; i++)
        diff |= computed_tag[i] ^ tag[i];

    if (diff != 0) {
        memset(msg, 0, clen);   /* wipe on failure */
        return -1;
    }
    return 0;
}

/* ── Split operations for benchmarking ──────────────────── */

void forkskinny_safe_hash(const safe_key_t *ks,
                          const uint8_t nonce[SAFE_NONCE_LEN],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t tweak[16], c0[16], c1[16], padded[16];
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    int has_ad  = (adlen > 0);
    int has_msg = (mlen  > 0);

    /* AD */
    process_ad(ks, nonce, ad, adlen, has_msg, sigma);

    /* Message: fork each block, accumulate c1 only */
    if (has_msg) {
        uint8_t d_full = has_ad ? 0x4 : 0x6;
        uint8_t d_last = has_ad ? 0x5 : 0x7;

        size_t full = mlen / 16;
        size_t rem  = mlen % 16;

        for (size_t i = 0; i < full; i++) {
            build_tweak(tweak, d_full, (uint32_t)i, nonce);
            fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
            xor_block(sigma, sigma, c1, 16);
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

void forkskinny_safe_encrypt(const safe_key_t *ks,
                             const uint8_t nonce[SAFE_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct)
{
    uint8_t tweak[16], c0[16], c1[16], padded[16];
    int has_ad = (adlen > 0);

    uint8_t d_full = has_ad ? 0x4 : 0x6;
    uint8_t d_last = has_ad ? 0x5 : 0x7;

    size_t full = mlen / 16;
    size_t rem  = mlen % 16;

    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, d_full, (uint32_t)i, nonce);
        fork_encrypt(ks->key, tweak, msg + i * 16, c0, c1);
        memcpy(ct + i * 16, c0, 16);
    }

    if (rem > 0) {
        pad_block(padded, msg + full * 16, rem);
        build_tweak(tweak, d_last, (uint32_t)full, nonce);
        uint8_t zero_padded[16], ks_c0[16], ks_c1[16];
        memset(zero_padded, 0, 16);
        zero_padded[0] = 0x80;
        fork_encrypt(ks->key, tweak, zero_padded, ks_c0, ks_c1);
        for (size_t j = 0; j < rem; j++)
            ct[full * 16 + j] = msg[full * 16 + j] ^ ks_c0[j];
    }
}

void forkskinny_safe_decrypt(const safe_key_t *ks,
                             const uint8_t nonce[SAFE_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg)
{
    uint8_t tweak[16], padded[16], c1[16];
    int has_ad = (adlen > 0);
    
    uint8_t d_full = has_ad ? 0x4 : 0x6;
    uint8_t d_last = has_ad ? 0x5 : 0x7;

    size_t full = clen / 16;
    size_t rem  = clen % 16;

    for (size_t i = 0; i < full; i++) {
        build_tweak(tweak, d_full, (uint32_t)i, nonce);
        fork_decrypt(ks->key, tweak, ct + i * 16, msg + i * 16, c1);
    }

    if (rem > 0) {
        build_tweak(tweak, d_last, (uint32_t)full, nonce);
        uint8_t zero_padded[16], ks_c0[16], ks_c1[16];
        memset(zero_padded, 0, 16);
        zero_padded[0] = 0x80;
        fork_encrypt(ks->key, tweak, zero_padded, ks_c0, ks_c1);
        for (size_t j = 0; j < rem; j++)
            msg[full * 16 + j] = ct[full * 16 + j] ^ ks_c0[j];
    }
}

int forkskinny_safe_verify(const safe_key_t *ks,
                           const uint8_t nonce[SAFE_NONCE_LEN],
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t computed[SAFE_TAG_LEN];
    forkskinny_safe_hash(ks, nonce, ad, adlen, msg, mlen, computed);

    int diff = 0;
    for (int i = 0; i < SAFE_TAG_LEN; i++)
        diff |= computed[i] ^ tag[i];
    return (diff == 0) ? 0 : -1;
}