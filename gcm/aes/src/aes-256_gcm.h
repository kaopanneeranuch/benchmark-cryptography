#ifndef AES_256_GCM_H
#define AES_256_GCM_H

#include <stddef.h>
#include <stdint.h>

#define AES_GCM_NONCE_LEN 12
#define AES_GCM_TAG_LEN   16
#define AES128_KEY_LEN    16
#define AES256_KEY_LEN    32

extern uint32_t g_aes128_block_calls;
extern uint32_t g_aes256_block_calls;

void aes_gcm_counters_reset(void);
uint32_t aes_128_gcm_get_block_calls(void);
uint32_t aes_256_gcm_get_block_calls(void);

/* AES-128-GCM */
void aes_128_gcm_ctr_crypt(const uint8_t key[AES128_KEY_LEN],
                           const uint8_t iv[AES_GCM_NONCE_LEN],
                           const uint8_t *in, size_t len,
                           uint8_t *out);

void aes_128_gcm_auth(const uint8_t key[AES128_KEY_LEN],
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t tag[AES_GCM_TAG_LEN]);

int aes_128_gcm_verify(const uint8_t key[AES128_KEY_LEN],
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[AES_GCM_TAG_LEN]);

void aes_128_gcm_encrypt_auth(const uint8_t key[AES128_KEY_LEN],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *ct,
                              uint8_t tag[AES_GCM_TAG_LEN]);

int aes_128_gcm_decrypt_verify(const uint8_t key[AES128_KEY_LEN],
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[AES_GCM_TAG_LEN],
                               uint8_t *pt);

/* AES-256-GCM */
void aes_256_gcm_ctr_crypt(const uint8_t key[AES256_KEY_LEN],
                           const uint8_t iv[AES_GCM_NONCE_LEN],
                           const uint8_t *in, size_t len,
                           uint8_t *out);

void aes_256_gcm_auth(const uint8_t key[AES256_KEY_LEN],
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t tag[AES_GCM_TAG_LEN]);

int aes_256_gcm_verify(const uint8_t key[AES256_KEY_LEN],
                       const uint8_t *iv, size_t iv_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[AES_GCM_TAG_LEN]);

void aes_256_gcm_encrypt_auth(const uint8_t key[AES256_KEY_LEN],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *ct,
                              uint8_t tag[AES_GCM_TAG_LEN]);

int aes_256_gcm_decrypt_verify(const uint8_t key[AES256_KEY_LEN],
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[AES_GCM_TAG_LEN],
                               uint8_t *pt);

#endif /* AES_256_GCM_H */
