#ifndef AES_SW_H
#define AES_SW_H

#include <stdint.h>

/* Standalone pure-C AES-256 ECB block encrypt (no hardware, no Oberon). */
void aes_sw_encrypt_256(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);

#endif /* AES_SW_H */
