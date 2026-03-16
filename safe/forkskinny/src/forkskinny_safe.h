#ifndef FORKSKINNY_SAFE_H
#define FORKSKINNY_SAFE_H

#include <stdint.h>
#include <stddef.h>

#define SAFE_KEY_LEN    16
#define SAFE_NONCE_LEN  12
#define SAFE_TAG_LEN    16
#define SAFE_BLOCK_LEN  16

typedef struct {
    uint8_t key[SAFE_KEY_LEN];
} safe_key_t;

/* Key setup */
void forkskinny_safe_keygen(const uint8_t key[SAFE_KEY_LEN],
                            safe_key_t *ks);

/* Full AEAD */
void forkskinny_safe_encrypt_auth(const safe_key_t *ks,
                                  const uint8_t nonce[SAFE_NONCE_LEN],
                                  const uint8_t *ad, size_t adlen,
                                  const uint8_t *msg, size_t mlen,
                                  uint8_t *ct,
                                  uint8_t tag[SAFE_TAG_LEN]);

int  forkskinny_safe_decrypt_verify(const safe_key_t *ks,
                                    const uint8_t nonce[SAFE_NONCE_LEN],
                                    const uint8_t *ad, size_t adlen,
                                    const uint8_t *ct, size_t clen,
                                    const uint8_t tag[SAFE_TAG_LEN],
                                    uint8_t *msg);

/* Split operations for benchmarking */
void forkskinny_safe_hash(const safe_key_t *ks,
                          const uint8_t nonce[SAFE_NONCE_LEN],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[SAFE_TAG_LEN]);

void forkskinny_safe_encrypt(const safe_key_t *ks,
                             const uint8_t nonce[SAFE_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct);

void forkskinny_safe_decrypt(const safe_key_t *ks,
                             const uint8_t nonce[SAFE_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg);

int  forkskinny_safe_verify(const safe_key_t *ks,
                            const uint8_t nonce[SAFE_NONCE_LEN],
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *msg, size_t mlen,
                            const uint8_t tag[SAFE_TAG_LEN]);

#endif /* FORKSKINNY_SAFE_H */