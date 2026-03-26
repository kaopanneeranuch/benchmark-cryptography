#include "fenc.h"
#include "internal-forkskinny.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define FENC_N       16
#define FENC_TWO_N   32
#define FENC_KEY_LEN 16

void fenc(const uint8_t *key,
                const uint8_t iv[FENC_TWO_N],
                const uint8_t *in, size_t len,
                uint8_t *out)
{
    uint8_t tk[FENC_TWO_N];
    uint8_t ctrU[FENC_N];
    size_t offset = 0;

    memcpy(ctrU, iv, FENC_N);
    memcpy(tk, iv + FENC_N, FENC_N);

    /* Force tweak to 1 || V */
    tk[0] &= 0x7F;
    tk[0] |= 0x80;
    memcpy(tk + FENC_N, key, FENC_KEY_LEN);

    while (offset < len) {
        uint8_t stream[FENC_TWO_N];
        size_t take = (len - offset < FENC_TWO_N) ? (len - offset) : FENC_TWO_N;

        forkskinny_128_256_encrypt(tk, stream, stream + FENC_N, ctrU);

        for (size_t j = 0; j < take; ++j)
            out[offset + j] = (uint8_t)(in[offset + j] ^ stream[j]);

        offset += take;

        /* ctrU <- ctrU + 1 (big-endian) */
        for (int b = FENC_N - 1; b >= 0; --b) {
            ctrU[b] = (uint8_t)(ctrU[b] + 1U);
            if (ctrU[b] != 0U)
                break;
        }
    }
}