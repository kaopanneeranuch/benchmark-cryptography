#include "forkskinny_sct.h"
#include "forkskinny_tbc.h"
#include <string.h>

static void build_sct_tweak(uint8_t tweak[16], uint8_t domain,
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

void forkskinny_sct_encrypt(const uint8_t key[16],
                           const uint8_t nonce[12],
                           const uint8_t *msg, size_t mlen,
                           uint8_t *ct, uint8_t tag[16])
{
    uint8_t tweak[16], tmp[16], checksum[16], zero[16] = {0};
    memset(checksum, 0, 16);

    size_t full_blocks = mlen / 16;
    size_t last_len    = mlen % 16;

    /* Pass 1: Hash message -> checksum */
    for (size_t i = 0; i < full_blocks; i++) {
        build_sct_tweak(tweak, 0x0, (uint32_t)i, nonce);
        forkskinny_tbc(key, tweak, msg + i * 16, tmp);
        xor_block(checksum, tmp);
    }
    if (last_len > 0) {
        uint8_t padded[16];
        memset(padded, 0, 16);
        memcpy(padded, msg + full_blocks * 16, last_len);
        padded[last_len] = 0x80;
        build_sct_tweak(tweak, 0x2, (uint32_t)full_blocks, nonce);
        forkskinny_tbc(key, tweak, padded, tmp);
        xor_block(checksum, tmp);
    }

    /* Tag = E_K^{1,0,N}(checksum) */
    build_sct_tweak(tweak, 0x1, 0, nonce);
    forkskinny_tbc(key, tweak, checksum, tag);

    /* Pass 2: CTR encrypt using tag in tweak */
    uint8_t tag12[12];
    memcpy(tag12, tag, 12);

    for (size_t i = 0; i < full_blocks; i++) {
        build_sct_tweak(tweak, 0x4, (uint32_t)(i + 1), tag12);
        forkskinny_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < 16; j++)
            ct[i * 16 + j] = msg[i * 16 + j] ^ tmp[j];
    }
    if (last_len > 0) {
        build_sct_tweak(tweak, 0x5, (uint32_t)(full_blocks + 1), tag12);
        forkskinny_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < last_len; j++)
            ct[full_blocks * 16 + j] = msg[full_blocks * 16 + j] ^ tmp[j];
    }
}

int forkskinny_sct_decrypt(const uint8_t key[16],
                          const uint8_t nonce[12],
                          const uint8_t *ct, size_t clen,
                          const uint8_t tag[16],
                          uint8_t *msg)
{
    uint8_t tweak[16], tmp[16], zero[16] = {0};
    size_t full_blocks = clen / 16;
    size_t last_len    = clen % 16;

    /* Phase 1: Decrypt (CTR with supplied tag) */
    uint8_t tag12[12];
    memcpy(tag12, tag, 12);

    for (size_t i = 0; i < full_blocks; i++) {
        build_sct_tweak(tweak, 0x4, (uint32_t)(i + 1), tag12);
        forkskinny_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < 16; j++)
            msg[i * 16 + j] = ct[i * 16 + j] ^ tmp[j];
    }
    if (last_len > 0) {
        build_sct_tweak(tweak, 0x5, (uint32_t)(full_blocks + 1), tag12);
        forkskinny_tbc(key, tweak, zero, tmp);
        for (size_t j = 0; j < last_len; j++)
            msg[full_blocks * 16 + j] = ct[full_blocks * 16 + j] ^ tmp[j];
    }

    /* Phase 2: Recompute tag from plaintext */
    uint8_t checksum[16];
    memset(checksum, 0, 16);

    for (size_t i = 0; i < full_blocks; i++) {
        build_sct_tweak(tweak, 0x0, (uint32_t)i, nonce);
        forkskinny_tbc(key, tweak, msg + i * 16, tmp);
        xor_block(checksum, tmp);
    }
    if (last_len > 0) {
        uint8_t padded[16];
        memset(padded, 0, 16);
        memcpy(padded, msg + full_blocks * 16, last_len);
        padded[last_len] = 0x80;
        build_sct_tweak(tweak, 0x2, (uint32_t)full_blocks, nonce);
        forkskinny_tbc(key, tweak, padded, tmp);
        xor_block(checksum, tmp);
    }

    uint8_t computed_tag[16];
    build_sct_tweak(tweak, 0x1, 0, nonce);
    forkskinny_tbc(key, tweak, checksum, computed_tag);

    /* Verify tag */
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    return diff == 0 ? 0 : -1;
}
