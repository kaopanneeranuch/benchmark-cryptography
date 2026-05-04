#ifndef GCTR3_H
#define GCTR3_H

#include <stddef.h>
#include <stdint.h>

#define GCTR3_N           16u
#define GCTR3_TWO_N       32u
#define GCTR3_KEY_LEN     16u
#define GCTR3_BK_BRANCHES  8u   /* Butterknife max branches */

/* GCTR-3 / ForkSkinny */
void gctr_3_forkskinny(const uint8_t key[GCTR3_KEY_LEN],
                       const uint8_t R[GCTR3_N],
                       const uint8_t N[GCTR3_N],
                       const uint8_t *in, size_t len,
                       uint8_t *out);

void gctr_3_forkskinny_iv(const uint8_t key[GCTR3_KEY_LEN],
                          const uint8_t iv[GCTR3_TWO_N],
                          const uint8_t *in, size_t len,
                          uint8_t *out);

/* GCTR-3 / Butterknife */
void gctr_3_butterknife(const uint8_t key[GCTR3_KEY_LEN],
                        const uint8_t R[GCTR3_N],
                        const uint8_t N[GCTR3_N],
                        const uint8_t *in, size_t len,
                        uint8_t *out,
                        uint8_t num_branches);

void gctr_3_butterknife_iv(const uint8_t key[GCTR3_KEY_LEN],
                           const uint8_t iv[GCTR3_TWO_N],
                           const uint8_t *in, size_t len,
                           uint8_t *out,
                           uint8_t num_branches);

void gctr_3_butterknife_iv_full(const uint8_t key[GCTR3_KEY_LEN],
                                const uint8_t iv[GCTR3_TWO_N],
                                const uint8_t *in, size_t len,
                                uint8_t *out);

/* GCTR-3' / ForkSkinny */
void gctr_3_prime(const uint8_t *key,
                  const uint8_t tag[GCTR3_TWO_N],
                  const uint8_t *in, size_t len,
                  uint8_t *out);

/* GCTR-3' / Butterknife */
void gctr_3_prime_butterknife(const uint8_t key[GCTR3_KEY_LEN],
                              const uint8_t tag[GCTR3_TWO_N],
                              const uint8_t *in, size_t len,
                              uint8_t *out);

void gctr_3_prime_butterknife_rn(const uint8_t key[GCTR3_KEY_LEN],
                                 const uint8_t R[GCTR3_N],
                                 const uint8_t N[GCTR3_N],
                                 const uint8_t *in, size_t len,
                                 uint8_t *out);

#endif
