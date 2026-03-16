#ifndef FORKSKINNY_ZAFE_H
#define FORKSKINNY_ZAFE_H

#include <stdint.h>
#include <stddef.h>

#define ZAFE_KEY_LEN    16
#define ZAFE_NONCE_LEN  12
#define ZAFE_TAG_LEN    16
#define ZAFE_BLOCK_LEN  16

typedef struct {
    uint8_t key[ZAFE_KEY_LEN];
} zafe_key_t;

/* Key setup */
void forkskinny_zafe_keygen(const uint8_t key[ZAFE_KEY_LEN],
                            zafe_key_t *ks);

/* Full AEAD (paper §5) */
void forkskinny_zafe_encrypt_auth(const zafe_key_t *ks,
                                  const uint8_t nonce[ZAFE_NONCE_LEN],
                                  const uint8_t *ad, size_t adlen,
                                  const uint8_t *msg, size_t mlen,
                                  uint8_t *ct,
                                  uint8_t tag[ZAFE_TAG_LEN]);

int  forkskinny_zafe_decrypt_verify(const zafe_key_t *ks,
                                    const uint8_t nonce[ZAFE_NONCE_LEN],
                                    const uint8_t *ad, size_t adlen,
                                    const uint8_t *ct, size_t clen,
                                    const uint8_t tag[ZAFE_TAG_LEN],
                                    uint8_t *msg);

/* Split operations for benchmarking */
void forkskinny_zafe_hash(const zafe_key_t *ks,
                          const uint8_t nonce[ZAFE_NONCE_LEN],
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[ZAFE_TAG_LEN]);

void forkskinny_zafe_encrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct);

void forkskinny_zafe_decrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg);

int  forkskinny_zafe_verify(const zafe_key_t *ks,
                            const uint8_t nonce[ZAFE_NONCE_LEN],
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *msg, size_t mlen,
                            const uint8_t tag[ZAFE_TAG_LEN]);

#endif /* FORKSKINNY_ZAFE_H */