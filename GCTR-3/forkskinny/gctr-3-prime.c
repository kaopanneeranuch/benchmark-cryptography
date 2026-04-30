/* gctr-3-prime.c */
#include "gctr-3-prime.h"
#include "internal-forkskinny.h"

#include <string.h>

static void gctr3p_xor_block(uint8_t out[GCTR3P_N],
                              const uint8_t a[GCTR3P_N],
                              const uint8_t b[GCTR3P_N])
{
    for (size_t i = 0; i < GCTR3P_N; ++i)
        out[i] = (uint8_t)(a[i] ^ b[i]);
}

static void gctr3p_set_domain_10(uint8_t tweak[GCTR3P_N])
{
    tweak[0] &= 0x3Fu;
    tweak[0] |= 0x80u;
}

static void gctr3p_inc_be(uint8_t x[GCTR3P_N])
{
    for (int i = (int)GCTR3P_N - 1; i >= 0; --i) {
        x[i] = (uint8_t)(x[i] + 1u);
        if (x[i] != 0u)
            break;
    }
}

/*
 * GCTR'-2-3 (forkskinny):
 *   T_j = (R XOR <j>) with last two bits forced to 10  (domain separation)
 *   X_j = N  (fixed: second n-bit half of the SuperSonic tag)
 *
 * tag = R || N  (32 bytes)
 */
void gctr_3_prime(const uint8_t *key,
                  const uint8_t tag[GCTR3P_TWO_N],
                  const uint8_t *in, size_t len,
                  uint8_t *out)
{
    uint8_t tk[GCTR3P_TWO_N];
    uint8_t j_enc[GCTR3P_N];
    size_t offset = 0u;

    const uint8_t *R = tag;
    const uint8_t *N = tag + GCTR3P_N;

    memset(j_enc, 0, sizeof(j_enc));
    memcpy(tk + GCTR3P_N, key, GCTR3P_KEY_LEN);

    while (offset < len) {
        uint8_t stream[GCTR3P_TWO_N];
        size_t remaining = len - offset;
        size_t take = remaining < GCTR3P_TWO_N ? remaining : GCTR3P_TWO_N;

        gctr3p_inc_be(j_enc);

        /* T_j = R XOR <j>, then force domain bits to 10 */
        gctr3p_xor_block(tk, R, j_enc);
        gctr3p_set_domain_10(tk);

        /* X_j = N (fixed for the whole message) */
        if (remaining <= GCTR3P_N)
            forkskinny_128_256_encrypt(tk, stream, NULL, N);
        else
            forkskinny_128_256_encrypt(tk, stream, stream + GCTR3P_N, N);

        for (size_t j = 0; j < take; ++j)
            out[offset + j] = (uint8_t)(in[offset + j] ^ stream[j]);

        offset += take;
    }
}
