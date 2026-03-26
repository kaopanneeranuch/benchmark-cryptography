#include "gctr-3-prime-bk.h"
#include "butterknife.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void xor_block_128(uint8_t out[GCTR3P_BK_N],
                          const uint8_t a[GCTR3P_BK_N],
                          const uint8_t b[GCTR3P_BK_N])
{
    for (size_t i = 0; i < GCTR3P_BK_N; ++i)
        out[i] = (uint8_t)(a[i] ^ b[i]);
}

/* Increment a 128-bit big-endian counter in place. */
static void inc_be_128(uint8_t x[GCTR3P_BK_N])
{
    for (int i = (int)GCTR3P_BK_N - 1; i >= 0; --i) {
        x[i] = (uint8_t)(x[i] + 1u);
        if (x[i] != 0u)
            break;
    }
}

/*
 * Force the two domain bits to 10.
 *
 * This matches your earlier ForkSkinny helper:
 *   tweak[0] &= 0x3F;
 *   tweak[0] |= 0x80;
 *
 * If your bit numbering/serialization is different, adjust this helper.
 */
static void gctr3p_bk_set_domain_10(uint8_t tweak[GCTR3P_BK_N])
{
    tweak[0] &= 0x3Fu;
    tweak[0] |= 0x80u;
}

void gctr_3_prime_butterknife_rn(const uint8_t key[GCTR3P_BK_KEY_LEN],
                                 const uint8_t R[GCTR3P_BK_N],
                                 const uint8_t N[GCTR3P_BK_N],
                                 const uint8_t *in, size_t len,
                                 uint8_t *out)
{
    uint8_t tweakey[GCTR3P_BK_TWO_N];                  /* tweak || key */
    uint8_t j_enc[GCTR3P_BK_N];                        /* <j> */
    uint8_t stream[GCTR3P_BK_N * GCTR3P_BK_BRANCHES]; /* 32 bytes */
    size_t offset = 0u;

    memset(j_enc, 0, sizeof(j_enc));
    memcpy(tweakey + GCTR3P_BK_N, key, GCTR3P_BK_KEY_LEN);

    while (offset < len) {
        size_t take = len - offset;
        if (take > sizeof(stream))
            take = sizeof(stream);

        /* j starts at 1 */
        inc_be_128(j_enc);

        /* T_j = R xor <j>, then force domain bits to 10 */
        xor_block_128(tweakey, R, j_enc);
        gctr3p_bk_set_domain_10(tweakey);

        /* X_j = N (fixed for the whole message) */
        butterknife_256_encrypt(tweakey, stream, N, GCTR3P_BK_BRANCHES);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}

void gctr_3_prime_butterknife(const uint8_t key[GCTR3P_BK_KEY_LEN],
                              const uint8_t tag[GCTR3P_BK_TWO_N],
                              const uint8_t *in, size_t len,
                              uint8_t *out)
{
    const uint8_t *R = tag;
    const uint8_t *N = tag + GCTR3P_BK_N;

    gctr_3_prime_butterknife_rn(key, R, N, in, len, out);
}