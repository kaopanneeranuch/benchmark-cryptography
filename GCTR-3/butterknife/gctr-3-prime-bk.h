#ifndef GCTR_3_PRIME_BK_H
#define GCTR_3_PRIME_BK_H

#include <stddef.h>
#include <stdint.h>

#define GCTR3P_BK_N         16u
#define GCTR3P_BK_TWO_N     32u
#define GCTR3P_BK_KEY_LEN   16u
#define GCTR3P_BK_BRANCHES   8u   

void gctr_3_prime_butterknife(const uint8_t key[GCTR3P_BK_KEY_LEN],
                              const uint8_t tag[GCTR3P_BK_TWO_N],
                              const uint8_t *in, size_t len,
                              uint8_t *out);

/* Same thing, but with R and N passed explicitly. */
void gctr_3_prime_butterknife_rn(const uint8_t key[GCTR3P_BK_KEY_LEN],
                                 const uint8_t R[GCTR3P_BK_N],
                                 const uint8_t N[GCTR3P_BK_N],
                                 const uint8_t *in, size_t len,
                                 uint8_t *out);

#endif