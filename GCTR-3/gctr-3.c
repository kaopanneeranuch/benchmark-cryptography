#include "gctr-3.h"
#include "internal-forkskinny.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define GCTR3_N       16
#define GCTR3_TWO_N   32
#define GCTR3_KEY_LEN 16

void gctr_crypt(const uint8_t *key,
                       const uint8_t *iv,
                       const uint8_t *in, size_t len,
                       uint8_t *out)
{
    uint8_t tk[GCTR3_TWO_N];
    uint8_t ctrU[GCTR3_N];
    size_t offset = 0;

    /* tk = (1 || V) || K, ctrU = U where iv = U || V */
    memcpy(ctrU, iv, GCTR3_N);
    memcpy(tk, iv + GCTR3_N, GCTR3_N);
    tk[0] &= 0x7FU;
    tk[0] |= 0x80U;
    memcpy(tk + GCTR3_N, key, GCTR3_KEY_LEN);

    while (offset < len) {
        uint8_t stream[GCTR3_TWO_N];
        size_t take = (len - offset < GCTR3_TWO_N) ? (len - offset) : GCTR3_TWO_N;

        forkskinny_128_256_encrypt(tk, stream, stream + GCTR3_N, ctrU);

        for (size_t j = 0; j < take; ++j) {
            out[offset + j] = (uint8_t)(in[offset + j] ^ stream[j]);
        }

        offset += take;

        for (int b = GCTR3_N - 1; b >= 0; --b) {
            ctrU[b] = (uint8_t)(ctrU[b] + 1U);
            if (ctrU[b] != 0U) {
                break;
            }
        }
    }
}
