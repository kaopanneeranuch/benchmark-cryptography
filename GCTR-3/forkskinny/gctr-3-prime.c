/* gctr-3-prime.c */
#include "gctr-3-prime.h"
#include "internal-forkskinny.h"

#include <string.h>

static void gctr3p_set_domain_10(uint8_t tweak_part[GCTR3P_N])
{
    tweak_part[0] &= 0x3Fu;
    tweak_part[0] |= 0x80u;   
}

void gctr_3_prime(const uint8_t *key,
                  const uint8_t tag[GCTR3P_TWO_N],
                  const uint8_t *in, size_t len,
                  uint8_t *out)
{
    uint8_t tk[GCTR3P_TWO_N];
    uint8_t ctrU[GCTR3P_N];
    size_t offset = 0u;

    const uint8_t *R = tag;               /* first n bits */
    const uint8_t *N = tag + GCTR3P_N;    /* second n bits */

    memcpy(ctrU, N, GCTR3P_N);
    memcpy(tk, R, GCTR3P_N);
    gctr3p_set_domain_10(tk);
    memcpy(tk + GCTR3P_N, key, GCTR3P_KEY_LEN);

    while (offset < len) {
        uint8_t stream[GCTR3P_TWO_N];
        size_t remaining = len - offset;
        size_t take = remaining < GCTR3P_TWO_N ? remaining : GCTR3P_TWO_N;

        /* Skip the right branch (C1) when only one output block is needed. */
        if (remaining <= GCTR3P_N)
            forkskinny_128_256_encrypt(tk, stream, NULL, ctrU);
        else
            forkskinny_128_256_encrypt(tk, stream, stream + GCTR3P_N, ctrU);

        for (size_t j = 0; j < take; ++j) {
            out[offset + j] = (uint8_t)(in[offset + j] ^ stream[j]);
        }

        offset += take;

        /* increment ctrU as a big-endian counter */
        for (int b = (int)GCTR3P_N - 1; b >= 0; --b) {
            ctrU[b] = (uint8_t)(ctrU[b] + 1u);
            if (ctrU[b] != 0u)
                break;
        }
    }
}