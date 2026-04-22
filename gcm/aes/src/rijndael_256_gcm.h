#ifndef RIJNDAEL_256_GCM_H
#define RIJNDAEL_256_GCM_H

#include <stddef.h>
#include <stdint.h>

#define RIJNDAEL256_GCM_NONCE_LEN  12
#define RIJNDAEL256_GCM_TAG_LEN    16
#define RIJNDAEL256_KEY_LEN        32  /* 256-bit key */
#define RIJNDAEL256_BLOCK_LEN      32  /* 256-bit block */

extern uint32_t g_rijndael256_block_calls;

void rijndael256_gcm_counters_reset(void);
uint32_t rijndael256_gcm_get_block_calls(void);

/* Rijndael-256-GCM */
void rijndael256_gcm_ctr_crypt(const uint8_t key[RIJNDAEL256_KEY_LEN],
                               const uint8_t iv[RIJNDAEL256_GCM_NONCE_LEN],
                               const uint8_t *in, size_t len,
                               uint8_t *out);

void rijndael256_gcm_auth(const uint8_t key[RIJNDAEL256_KEY_LEN],
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct, size_t ct_len,
                          uint8_t tag[RIJNDAEL256_GCM_TAG_LEN]);

int rijndael256_gcm_verify(const uint8_t key[RIJNDAEL256_KEY_LEN],
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[RIJNDAEL256_GCM_TAG_LEN]);

void rijndael256_gcm_encrypt_auth(const uint8_t key[RIJNDAEL256_KEY_LEN],
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint8_t *ct,
                                  uint8_t tag[RIJNDAEL256_GCM_TAG_LEN]);

int rijndael256_gcm_decrypt_verify(const uint8_t key[RIJNDAEL256_KEY_LEN],
                                   const uint8_t *iv, size_t iv_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ct, size_t ct_len,
                                   const uint8_t tag[RIJNDAEL256_GCM_TAG_LEN],
                                   uint8_t *pt);

#endif /* RIJNDAEL_256_GCM_H */
