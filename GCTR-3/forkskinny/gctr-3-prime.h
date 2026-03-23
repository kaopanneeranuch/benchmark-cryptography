#ifndef GCTR_3_PRIME_H
#define GCTR_3_PRIME_H

#include <stddef.h>
#include <stdint.h>

#define GCTR3P_N       16u
#define GCTR3P_TWO_N   32u
#define GCTR3P_KEY_LEN 16u

void gctr_3_prime(const uint8_t *key,
                  const uint8_t tag[GCTR3P_TWO_N],
                  const uint8_t *in, size_t len,
                  uint8_t *out);

#endif