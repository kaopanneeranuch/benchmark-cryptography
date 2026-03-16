#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "butterknife.h"
#include "butterknife_zafe.h"

/* Build ZAFE tweak: [domain(4b)|counter(28b)] [aux(12B)] */
static void build_zafe_tweak(uint8_t tweak[16], uint8_t domain,
                             uint32_t counter, const uint8_t aux[12])
{
    tweak[0] = (uint8_t)((domain << 4) | ((counter >> 24) & 0x0F));
    tweak[1] = (uint8_t)((counter >> 16) & 0xFF);
    tweak[2] = (uint8_t)((counter >>  8) & 0xFF);
    tweak[3] = (uint8_t)( counter        & 0xFF);
    memcpy(tweak + 4, aux, 12);
}

static void xor_block(uint8_t dst[16], const uint8_t src[16])
{
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

/* ── Butterknife-256 TBC primitive (1 branch) ───────────── */
void butterknife_tbc(const uint8_t key[16], const uint8_t tweak[16],
                    const uint8_t in[16], uint8_t out[16])
{
    uint8_t tk[32];
    memcpy(tk, tweak, 16);
    memcpy(tk + 16, key, 16);
    butterknife_256_encrypt(tk, out, in, 1);
}

/* ── ZAFE Encrypt ───────────────────────────────────────── */
void butterknife_zafe_encrypt(const uint8_t key[16],
                             const uint8_t nonce[12],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct, uint8_t tag[16])
{
    uint8_t tweak[16], tmp[16], sigma[16], zero[16] = {0};
    memset(sigma, 0, 16);

    size_t full_blocks = mlen / 16;
    size_t last_len    = mlen % 16;

    /* ── Pass 1: Hash message → sigma → Tag ── */
    for (size_t i = 0; i < full_blocks; i++) {
        build_zafe_tweak(tweak, 0x8, (uint32_t)i, nonce);
        butterknife_tbc(key, tweak, msg + i * 16, tmp);
        xor_block(sigma, tmp);
    }
    if (last_len > 0) {
        uint8_t padded[16];
        memset(padded, 0, 16);
        memcpy(padded, msg + full_blocks * 16, last_len);
        padded[last_len] = 0x80;                       /* 10* pad */
        build_zafe_tweak(tweak, 0xA, (uint32_t)full_blocks, nonce);
        butterknife_tbc(key, tweak, padded, tmp);
        xor_block(sigma, tmp);
    }

    build_zafe_tweak(tweak, 0x9, 0, nonce);
    butterknife_tbc(key, tweak, sigma, tag);

    /* ── Pass 2: CTR encrypt using Tag in tweak aux ── */
    uint8_t tag12[12];
    memcpy(tag12, tag, 12);

    for (size_t i = 0; i < full_blocks; i++) {
        build_zafe_tweak(tweak, 0xC, (uint32_t)(i + 1), tag12);
        butterknife_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < 16; j++)
            ct[i * 16 + j] = msg[i * 16 + j] ^ tmp[j];
    }
    if (last_len > 0) {
        build_zafe_tweak(tweak, 0xD, (uint32_t)(full_blocks + 1), tag12);
        butterknife_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < last_len; j++)
            ct[full_blocks * 16 + j] = msg[full_blocks * 16 + j] ^ tmp[j];
    }
}

/* ── ZAFE Decrypt (returns 0 on tag-ok, -1 on fail) ────── */
int butterknife_zafe_decrypt(const uint8_t key[16],
                            const uint8_t nonce[12],
                            const uint8_t *ct, size_t clen,
                            const uint8_t tag[16],
                            uint8_t *msg)
{
    uint8_t tweak[16], tmp[16], zero[16] = {0};
    size_t full_blocks = clen / 16;
    size_t last_len    = clen % 16;

    /* ── Phase 1: CTR decrypt using supplied Tag ── */
    uint8_t tag12[12];
    memcpy(tag12, tag, 12);

    for (size_t i = 0; i < full_blocks; i++) {
        build_zafe_tweak(tweak, 0xC, (uint32_t)(i + 1), tag12);
        butterknife_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < 16; j++)
            msg[i * 16 + j] = ct[i * 16 + j] ^ tmp[j];
    }
    if (last_len > 0) {
        build_zafe_tweak(tweak, 0xD, (uint32_t)(full_blocks + 1), tag12);
        butterknife_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < last_len; j++)
            msg[full_blocks * 16 + j] = ct[full_blocks * 16 + j] ^ tmp[j];
    }

    /* ── Phase 2: Recompute tag from recovered plaintext ── */
    uint8_t sigma[16];
    memset(sigma, 0, 16);

    for (size_t i = 0; i < full_blocks; i++) {
        build_zafe_tweak(tweak, 0x8, (uint32_t)i, nonce);
        butterknife_tbc(key, tweak, msg + i * 16, tmp);
        xor_block(sigma, tmp);
    }
    if (last_len > 0) {
        uint8_t padded[16];
        memset(padded, 0, 16);
        memcpy(padded, msg + full_blocks * 16, last_len);
        padded[last_len] = 0x80;
        build_zafe_tweak(tweak, 0xA, (uint32_t)full_blocks, nonce);
        butterknife_tbc(key, tweak, padded, tmp);
        xor_block(sigma, tmp);
    }

    uint8_t computed_tag[16];
    build_zafe_tweak(tweak, 0x9, 0, nonce);
    butterknife_tbc(key, tweak, sigma, computed_tag);

    /* ── Phase 3: Constant-time tag verify ── */
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    return diff == 0 ? 0 : -1;
}
