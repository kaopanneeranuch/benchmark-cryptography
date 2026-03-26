#ifndef GCTR_3_BK_H
#define GCTR_3_BK_H

#include <stddef.h>
#include <stdint.h>

#define GCTR3_BK_N       16u
#define GCTR3_BK_TWO_N   32u
#define GCTR3_BK_KEY_LEN 16u

void gctr_3_butterknife(const uint8_t key[GCTR3_BK_KEY_LEN],
                        const uint8_t R[GCTR3_BK_N],
                        const uint8_t N[GCTR3_BK_N],
                        const uint8_t *in, size_t len,
                        uint8_t *out,
                        uint8_t num_branches);

void gctr_3_butterknife_iv(const uint8_t key[GCTR3_BK_KEY_LEN],
                           const uint8_t iv[GCTR3_BK_TWO_N],
                           const uint8_t *in, size_t len,
                           uint8_t *out,
                           uint8_t num_branches);

void gctr_3_butterknife_iv_full(const uint8_t key[GCTR3_BK_KEY_LEN],
                                const uint8_t iv[GCTR3_BK_TWO_N],
                                const uint8_t *in, size_t len,
                                uint8_t *out);

#endif