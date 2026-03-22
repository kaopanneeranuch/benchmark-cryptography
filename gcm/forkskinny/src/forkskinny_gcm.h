#ifndef FORKSKINNY_H
#define FORKSKINNY_H
#include <stdint.h>
#include <stddef.h>

void forkskinny_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void forkskinny_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *pt, size_t len, uint8_t *ct);

void forkskinny_gcm_encrypt(const uint8_t key[16],
					   const uint8_t *iv, size_t iv_len,
					   const uint8_t *aad, size_t aad_len,
					   const uint8_t *pt, size_t len,
					   uint8_t *ct, uint8_t tag[16]);

int forkskinny_gcm_decrypt(const uint8_t key[16],
					  const uint8_t *iv, size_t iv_len,
					  const uint8_t *aad, size_t aad_len,
					  const uint8_t *ct, size_t len,
					  const uint8_t tag[16], uint8_t *pt);

/* Additional helpers for benchmarking */
void forkskinny_gcm_keygen(const uint8_t key[16]);
void forkskinny_gcm_compute_H(const uint8_t key[16], uint8_t H[16]);
void forkskinny_gcm_compute_EkJ0(const uint8_t key[16], const uint8_t nonce[12], uint8_t EkJ0[16]);
#endif