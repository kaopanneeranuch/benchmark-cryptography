#ifndef AESGCM_H
#define AESGCM_H
#include <stdint.h>
#include <stddef.h>

void aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void aes_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *pt, size_t len, uint8_t *ct);

void aes_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
					   const uint8_t *aad, size_t aad_len,
					   const uint8_t *pt, size_t len,
					   uint8_t *ct, uint8_t tag[16]);

int aes_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
					  const uint8_t *aad, size_t aad_len,
					  const uint8_t *ct, size_t len,
					  const uint8_t tag[16], uint8_t *pt);
#endif