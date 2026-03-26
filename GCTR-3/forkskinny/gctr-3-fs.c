#include "gctr-3-fs.h"
#include "internal-forkskinny.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GCTR3_N       16
#define GCTR3_TWO_N   32
#define GCTR3_KEY_LEN 16

static void xor_block_128(uint8_t out[GCTR3_N],
                          const uint8_t a[GCTR3_N],
                          const uint8_t b[GCTR3_N])
{
    for (size_t i = 0; i < GCTR3_N; ++i)
        out[i] = (uint8_t)(a[i] ^ b[i]);
}

/* Increment a 128-bit big-endian counter in place. */
static void inc_be_128(uint8_t x[GCTR3_N])
{
    for (int i = GCTR3_N - 1; i >= 0; --i) {
        x[i] = (uint8_t)(x[i] + 1u);
        if (x[i] != 0u)
            break;
    }
}

/*
 *   T_j = R xor <j>
 *   X_j = N
 *
 * R: 16-byte random IV part
 * N: 16-byte nonce/input part
 *
 * Encryption and decryption are the same function.
 */
void gctr_3_forkskinny(const uint8_t key[GCTR3_KEY_LEN],
                       const uint8_t R[GCTR3_N],
                       const uint8_t N[GCTR3_N],
                       const uint8_t *in, size_t len,
                       uint8_t *out)
{
    uint8_t tk[GCTR3_TWO_N];         /* tweak || key */
    uint8_t j_enc[GCTR3_N];          /* <j> */
    uint8_t stream[GCTR3_TWO_N];
    size_t offset = 0;

    memset(j_enc, 0, sizeof(j_enc));
    memcpy(tk + GCTR3_N, key, GCTR3_KEY_LEN);

    while (offset < len) {
        size_t take = len - offset;
        if (take > GCTR3_TWO_N)
            take = GCTR3_TWO_N;

        /* j starts at 1 */
        inc_be_128(j_enc);

        /* T_j = R xor <j> */
        xor_block_128(tk, R, j_enc);

        /* X_j = N (fixed for the whole message) */
        forkskinny_128_256_encrypt(tk, stream, stream + GCTR3_N, N);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}