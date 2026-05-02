#ifndef GCTR_3_FS_H
#define GCTR_3_FS_H

#include <stddef.h>
#include <stdint.h>

#define GCTR3_N       16u
#define GCTR3_TWO_N   32u
#define GCTR3_KEY_LEN 16u

void gctr_3_forkskinny(const uint8_t key[GCTR3_KEY_LEN],
                       const uint8_t R[GCTR3_N],
                       const uint8_t N[GCTR3_N],
                       const uint8_t *in, size_t len,
                       uint8_t *out);

/*
 * Convenience wrapper with iv = R || N.
 */
void gctr_3_forkskinny_iv(const uint8_t key[GCTR3_KEY_LEN],
                          const uint8_t iv[GCTR3_TWO_N],
                          const uint8_t *in, size_t len,
                          uint8_t *out);

#endif