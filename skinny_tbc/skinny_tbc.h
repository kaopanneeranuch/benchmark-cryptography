#ifndef SKINNY_TBC_H
#define SKINNY_TBC_H

#include <stdint.h>

/*
 * SKINNY-128-128 tweakable block cipher.
 *   key:    16 bytes
 *   tweak:  16 bytes
 *   input:  16 bytes plaintext
 *   output: 16 bytes ciphertext
 */
void skinny_encrypt(const uint8_t key[16],
                    const uint8_t tweak[16],
                    const uint8_t input[16],
                    uint8_t output[16]);

void skinny_decrypt(const uint8_t key[16],
                    const uint8_t tweak[16],
                    const uint8_t input[16],
                    uint8_t output[16]);

#endif /* SKINNY_TBC_H */