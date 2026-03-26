#ifndef GCTR_3_FS_H
#define GCTR_3_FS_H

#include <stddef.h>
#include <stdint.h>

#define GCTR3_N       16u
#define GCTR3_TWO_N   32u
#define GCTR3_KEY_LEN 16u

/*
 * GCTR-3 over ForkSkinny-128-256.
 *
 * key: 16-byte secret key
 * R:   16-byte tweak base
 * N:   16-byte fixed input block
 * in:  input buffer
 * len: input length in bytes
 * out: output buffer
 *
 * Encryption and decryption are identical.
 */
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