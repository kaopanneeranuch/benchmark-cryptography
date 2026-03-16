#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <stddef.h>
uint64_t load_64(const uint8_t *b);
void store_64(uint8_t *b, uint64_t v);
void xor_block(uint8_t out[16], const uint8_t in[16]);
#endif