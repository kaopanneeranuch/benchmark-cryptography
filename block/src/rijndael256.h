#ifndef RIJNDAEL256_H
#define RIJNDAEL256_H

#include <stdint.h>

/* Rijndael with 256-bit block and 256-bit key (Nb=8, Nk=8, Nr=14) */
typedef struct {
    uint32_t rk[120]; /* (Nr+1)*Nb round key words */
} rijndael256_ctx_t;

void rijndael256_set_key(rijndael256_ctx_t *ctx, const uint8_t key[32]);
void rijndael256_encrypt(const rijndael256_ctx_t *ctx,
                         const uint8_t in[32], uint8_t out[32]);

#endif /* RIJNDAEL256_H */
