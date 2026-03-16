#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>

#include "butterknife.h"
#include "butterknife_safe.h"

/* Build SAFE tweak: [domain(4b)|counter(28b)] [nonce(12B)] */
static void build_safe_tweak(uint8_t tweak[16], uint8_t domain,
                             uint32_t counter, const uint8_t nonce[12])
{
    tweak[0] = (uint8_t)((domain << 4) | ((counter >> 24) & 0x0F));
    tweak[1] = (uint8_t)((counter >> 16) & 0xFF);
    tweak[2] = (uint8_t)((counter >>  8) & 0xFF);
    tweak[3] = (uint8_t)( counter        & 0xFF);
    memcpy(tweak + 4, nonce, 12);
}

static void xor_block(uint8_t dst[16], const uint8_t src[16])
{
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

/* 1-branch output (tag finalization) */
void butterknife_tbc(const uint8_t key[16], const uint8_t tweak[16],
                    const uint8_t in[16], uint8_t out[16])
{
    uint8_t tk[32];
    memcpy(tk, tweak, 16);
    memcpy(tk + 16, key, 16);
    butterknife_256_encrypt(tk, out, in, 1);
}

/* 2-branch output (encryption + auth in one call) */
void butterknife_tbc_fork(const uint8_t key[16], const uint8_t tweak[16],
                         const uint8_t in[16],
                         uint8_t out_b1[16], uint8_t out_b2[16])
{
    uint8_t tk[32];
    memcpy(tk, tweak, 16);
    memcpy(tk + 16, key, 16);
    uint8_t output[32];
    butterknife_256_encrypt(tk, output, in, 2);
    memcpy(out_b1, output, 16);       /* branch 1 = keystream */
    memcpy(out_b2, output + 16, 16);  /* branch 2 = auth mask */
}

/* ── SAFE Encrypt ───────────────────────────────────────── */
void butterknife_safe_encrypt(const uint8_t key[16],
                             const uint8_t nonce[12],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct, uint8_t tag[16])
{
    uint8_t tweak[16], ks[16], auth[16];
    static const uint8_t zero[16] = {0};
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    size_t full_blocks = mlen / 16;
    size_t last_len    = mlen % 16;

    /* Process full message blocks (1 TBC call → 2 outputs) */
    for (size_t i = 0; i < full_blocks; i++) {
        build_safe_tweak(tweak, 0x4, (uint32_t)i, nonce);
        butterknife_tbc_fork(key, tweak, zero, ks, auth);
        /* Encrypt: CTR */
        for (size_t j = 0; j < 16; j++)
            ct[i * 16 + j] = msg[i * 16 + j] ^ ks[j];
        /* Authenticate: accumulate (auth_mask ^ plaintext) */
        for (int j = 0; j < 16; j++)
            sigma[j] ^= auth[j] ^ msg[i * 16 + j];
    }

    /* Process partial last block */
    if (last_len > 0) {
        build_safe_tweak(tweak, 0x5, (uint32_t)full_blocks, nonce);
        butterknife_tbc_fork(key, tweak, zero, ks, auth);
        /* Encrypt partial */
        for (size_t j = 0; j < last_len; j++)
            ct[full_blocks * 16 + j] = msg[full_blocks * 16 + j] ^ ks[j];
        /* Auth: pad plaintext with 10* before XOR */
        uint8_t padded[16];
        memset(padded, 0, 16);
        memcpy(padded, msg + full_blocks * 16, last_len);
        padded[last_len] = 0x80;
        for (int j = 0; j < 16; j++)
            sigma[j] ^= auth[j] ^ padded[j];
    }

    /* Finalize tag: 1-branch only */
    build_safe_tweak(tweak, 0x1, 0, nonce);
    butterknife_tbc(key, tweak, sigma, tag);
}

/* ── SAFE Decrypt (returns 0 on tag-ok, -1 on fail) ────── */
int butterknife_safe_decrypt(const uint8_t key[16],
                            const uint8_t nonce[12],
                            const uint8_t *ct, size_t clen,
                            const uint8_t tag[16],
                            uint8_t *msg)
{
    uint8_t tweak[16], ks[16], auth[16];
    static const uint8_t zero[16] = {0};
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    size_t full_blocks = clen / 16;
    size_t last_len    = clen % 16;

    /* Process full blocks: same TBC calls recover keystream + auth */
    for (size_t i = 0; i < full_blocks; i++) {
        build_safe_tweak(tweak, 0x4, (uint32_t)i, nonce);
        butterknife_tbc_fork(key, tweak, zero, ks, auth);
        /* Decrypt: CTR */
        for (size_t j = 0; j < 16; j++)
            msg[i * 16 + j] = ct[i * 16 + j] ^ ks[j];
        /* Auth: accumulate (auth_mask ^ recovered_plaintext) */
        for (int j = 0; j < 16; j++)
            sigma[j] ^= auth[j] ^ msg[i * 16 + j];
    }

    /* Process partial last block */
    if (last_len > 0) {
        build_safe_tweak(tweak, 0x5, (uint32_t)full_blocks, nonce);
        butterknife_tbc_fork(key, tweak, zero, ks, auth);
        for (size_t j = 0; j < last_len; j++)
            msg[full_blocks * 16 + j] = ct[full_blocks * 16 + j] ^ ks[j];
        uint8_t padded[16];
        memset(padded, 0, 16);
        memcpy(padded, msg + full_blocks * 16, last_len);
        padded[last_len] = 0x80;
        for (int j = 0; j < 16; j++)
            sigma[j] ^= auth[j] ^ padded[j];
    }

    /* Recompute and verify tag */
    uint8_t computed_tag[16];
    build_safe_tweak(tweak, 0x1, 0, nonce);
    butterknife_tbc(key, tweak, sigma, computed_tag);

    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    return diff == 0 ? 0 : -1;
}
