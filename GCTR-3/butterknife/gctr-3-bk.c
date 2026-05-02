#include "gctr-3-bk.h"
#include "butterknife.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void xor_block_128(uint8_t out[GCTR3_BK_N],
                          const uint8_t a[GCTR3_BK_N],
                          const uint8_t b[GCTR3_BK_N])
{
    for (size_t i = 0; i < GCTR3_BK_N; ++i)
        out[i] = (uint8_t)(a[i] ^ b[i]);
}

/* Increment a 128-bit big-endian counter in place. */
static void inc_be_128(uint8_t x[GCTR3_BK_N])
{
    for (int i = (int)GCTR3_BK_N - 1; i >= 0; --i) {
        x[i] = (uint8_t)(x[i] + 1u);
        if (x[i] != 0u)
            break;
    }
}

void gctr_3_butterknife(const uint8_t key[GCTR3_BK_KEY_LEN],
                        const uint8_t R[GCTR3_BK_N],
                        const uint8_t N[GCTR3_BK_N],
                        const uint8_t *in, size_t len,
                        uint8_t *out,
                        uint8_t num_branches)
{
    uint8_t tweakey[GCTR3_BK_TWO_N];
    uint8_t j_enc[GCTR3_BK_N];
    uint8_t stream[GCTR3_BK_N * BUTTERKNIFE_MAX_BRANCHES];
    size_t offset = 0u;
    size_t chunk_len;

    if (num_branches == 0u || num_branches > BUTTERKNIFE_MAX_BRANCHES)
        return;

    /* tweakey = tweak || key */
    memcpy(tweakey + GCTR3_BK_N, key, GCTR3_BK_KEY_LEN);

    /* j starts at 1 */
    memset(j_enc, 0, sizeof(j_enc));

    while (offset < len) {
        size_t remaining = len - offset;
        /* Use only as many branches as needed for the remaining data. */
        size_t b = (remaining + GCTR3_BK_N - 1u) / GCTR3_BK_N;
        if (b > num_branches)
            b = num_branches;
        chunk_len = (size_t)GCTR3_BK_N * (size_t)b;
        size_t take = remaining < chunk_len ? remaining : chunk_len;

        inc_be_128(j_enc);            
        xor_block_128(tweakey, R, j_enc); /* tweak = R xor <j> */

        butterknife_256_encrypt(tweakey, stream, N, (uint8_t)b);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}

void gctr_3_butterknife_iv(const uint8_t key[GCTR3_BK_KEY_LEN],
                           const uint8_t iv[GCTR3_BK_TWO_N], 
                           const uint8_t *in, size_t len,
                           uint8_t *out,
                           uint8_t num_branches)
{
    gctr_3_butterknife(key, iv, iv + GCTR3_BK_N, in, len, out, num_branches);
}

void gctr_3_butterknife_iv_full(const uint8_t key[GCTR3_BK_KEY_LEN],
                                const uint8_t iv[GCTR3_BK_TWO_N],
                                const uint8_t *in, size_t len,
                                uint8_t *out)
{
    gctr_3_butterknife_iv(key, iv, in, len, out, BUTTERKNIFE_MAX_BRANCHES);
}