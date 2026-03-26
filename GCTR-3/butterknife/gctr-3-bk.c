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

/*
 * GCTR-3 shape over ButterKnife:
 *
 *   T_j = R xor <j>
 *   X_j = N
 *
 * key         : 16-byte secret key
 * R           : 16-byte tweak base
 * N           : 16-byte fixed input block
 * in / out    : input/output buffers (may overlap for in-place use)
 * len         : number of bytes to process
 * num_branches: 1..8
 *
 * Encryption and decryption are identical.
 */
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

    chunk_len = (size_t)GCTR3_BK_N * (size_t)num_branches;

    /* tweakey = tweak || key */
    memcpy(tweakey + GCTR3_BK_N, key, GCTR3_BK_KEY_LEN);

    /* j starts at 1 */
    memset(j_enc, 0, sizeof(j_enc));

    while (offset < len) {
        size_t take = len - offset;

        if (take > chunk_len)
            take = chunk_len;

        inc_be_128(j_enc);                 /* <j> */
        xor_block_128(tweakey, R, j_enc); /* tweak = R xor <j> */

        /* input block stays fixed as N */
        butterknife_256_encrypt(tweakey, stream, N, num_branches);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}

void gctr_3_butterknife_iv(const uint8_t key[GCTR3_BK_KEY_LEN],
                           const uint8_t iv[GCTR3_BK_TWO_N], /* iv = R || N */
                           const uint8_t *in, size_t len,
                           uint8_t *out,
                           uint8_t num_branches)
{
    gctr_3_butterknife(key, iv, iv + GCTR3_BK_N, in, len, out, num_branches);
}

/*
 * Convenience wrapper: use the full ButterKnife width (8 branches = 128 bytes/call).
 */
void gctr_3_butterknife_iv_full(const uint8_t key[GCTR3_BK_KEY_LEN],
                                const uint8_t iv[GCTR3_BK_TWO_N],
                                const uint8_t *in, size_t len,
                                uint8_t *out)
{
    gctr_3_butterknife_iv(key, iv, in, len, out, BUTTERKNIFE_MAX_BRANCHES);
}