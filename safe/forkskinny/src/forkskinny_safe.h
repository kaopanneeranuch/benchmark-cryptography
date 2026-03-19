#ifndef FORKSKINNY_SAFE_H
#define FORKSKINNY_SAFE_H

#include <stddef.h>
#include <stdint.h>

#define SAFE_KEY_LEN 16
#define SAFE_TAG_LEN 32

typedef struct {
    uint8_t key[SAFE_KEY_LEN];
} safe_key_t;

void forkskinny_safe_keygen(const uint8_t key[SAFE_KEY_LEN],
                            safe_key_t *ks);

void forkskinny_safe_auth(const safe_key_t *ks,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[SAFE_TAG_LEN]);

int forkskinny_safe_verify(const safe_key_t *ks,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[SAFE_TAG_LEN]);

void forkskinny_safe_encrypt(const safe_key_t *ks,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[SAFE_TAG_LEN]);

int forkskinny_safe_decrypt(const safe_key_t *ks,
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *ct, size_t clen,
                            const uint8_t tag[SAFE_TAG_LEN],
                            uint8_t *msg);
                            
void forkskinny_safe_fenc_encrypt(const safe_key_t *ks,
                                  const uint8_t tag[SAFE_TAG_LEN],
                                  const uint8_t *pt, size_t ptlen,
                                  uint8_t *ct);

void forkskinny_safe_fenc_decrypt(const safe_key_t *ks,
                                  const uint8_t tag[SAFE_TAG_LEN],
                                  const uint8_t *ct, size_t ctlen,
                                  uint8_t *pt);

#endif