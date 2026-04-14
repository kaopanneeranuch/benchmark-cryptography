#ifndef AESCTR_H
#define AESCTR_H
#include <stdint.h>
#include <stddef.h>

extern uint32_t g_aes_enc_calls;
void aes_counters_reset(void);

void aes_encrypt_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);
void aes_ctr_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *pt, size_t len, uint8_t *ct);

void aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
					   const uint8_t *aad, size_t aad_len,
					   const uint8_t *pt, size_t len,
					   uint8_t *ct, uint8_t tag[16]);

int aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
					  const uint8_t *aad, size_t aad_len,
					  const uint8_t *ct, size_t len,
					  const uint8_t tag[16], uint8_t *pt);

/* Public AES-256 GCM API (wrappers) */
void aes_256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
						 const uint8_t *pt, size_t len, uint8_t *ct);

void aes_256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
						 const uint8_t *ct, size_t len, uint8_t *pt);

void aes_256_gcm_auth(const uint8_t key[32],
					  const uint8_t *iv, size_t iv_len,
					  const uint8_t *aad, size_t aad_len,
					  const uint8_t *ct, size_t len,
					  uint8_t tag[16]);

int aes_256_gcm_verify(const uint8_t key[32],
					   const uint8_t *iv, size_t iv_len,
					   const uint8_t *aad, size_t aad_len,
					   const uint8_t *ct, size_t len,
					   const uint8_t tag[16]);

void aes_256_gcm_encrypt_auth(const uint8_t key[32],
							 const uint8_t *iv, size_t iv_len,
							 const uint8_t *aad, size_t aad_len,
							 const uint8_t *pt, size_t len,
							 uint8_t *ct, uint8_t tag[16]);

int aes_256_gcm_decrypt_verify(const uint8_t key[32],
							  const uint8_t *iv, size_t iv_len,
							  const uint8_t *aad, size_t aad_len,
							  const uint8_t *ct, size_t len,
							  const uint8_t tag[16], uint8_t *pt);
#endif