#include "fenc.h"
#include "internal-forkskinny.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define FENC_N       16
#define FENC_TWO_N   32
#define FENC_KEY_LEN 16

/*
 * FEnc(K, I, M):
 *   U || V <- [I]_(n+t)          (U = first n bytes, V = last t bytes)
 *   tweak  = 1 || V              (MSB of tweak forced to 1)
 *   block i input = U XOR <i-1>  (XOR with counter, not addition)
 */
void fenc(const uint8_t *key,
          const uint8_t iv[FENC_TWO_N],
          const uint8_t *in, size_t len,
          uint8_t *out)
{
    uint8_t tk[FENC_TWO_N];
    uint8_t j_enc[FENC_N];       /* counter j = i-1, starts at 0 */
    uint8_t block_in[FENC_N];    /* U XOR j */
    size_t offset = 0;

    const uint8_t *U = iv;            /* first n bytes */
    const uint8_t *V = iv + FENC_N;  /* last t bytes  */

    /* tweak = 1 || V: force MSB to 1 */
    memcpy(tk, V, FENC_N);
    tk[0] |= 0x80u;
    memcpy(tk + FENC_N, key, FENC_KEY_LEN);

    memset(j_enc, 0, sizeof(j_enc));

    while (offset < len) {
        uint8_t stream[FENC_TWO_N];
        size_t remaining = len - offset;
        size_t take = remaining < FENC_TWO_N ? remaining : FENC_TWO_N;

        /* block input = U XOR <j> (algorithm: U XOR i-1) */
        for (int k = 0; k < FENC_N; ++k)
            block_in[k] = U[k] ^ j_enc[k];

        if (remaining <= FENC_N)
            forkskinny_128_256_encrypt(tk, stream, NULL, block_in);
        else
            forkskinny_128_256_encrypt(tk, stream, stream + FENC_N, block_in);

        for (size_t j = 0; j < take; ++j)
            out[offset + j] = (uint8_t)(in[offset + j] ^ stream[j]);

        offset += take;

        /* increment counter j (big-endian) */
        for (int b = FENC_N - 1; b >= 0; --b) {
            j_enc[b] = (uint8_t)(j_enc[b] + 1u);
            if (j_enc[b] != 0u)
                break;
        }
    }
}
