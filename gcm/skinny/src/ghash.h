#ifndef GHASH_H
#define GHASH_H
#include <stdint.h>
#include <stddef.h>
void ghash(const uint8_t H[16], const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len, uint8_t out[16]);
#endif