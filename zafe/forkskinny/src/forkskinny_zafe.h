#ifndef FORKSKINNY_ZAFE_H
#define FORKSKINNY_ZAFE_H

#include <stddef.h>
#include <stdint.h>

#define ZAFE_KEY_LEN 32
#define ZAFE_TAG_LEN 32

typedef struct {
    uint8_t enc_key[16];
    uint8_t mac_key[16];
} zafe_key_t;

void forkskinny_zafe_keygen(const uint8_t key[ZAFE_KEY_LEN],
                            zafe_key_t *ks);

void forkskinny_zafe_hash(const zafe_key_t *ks,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[ZAFE_TAG_LEN]);

int forkskinny_zafe_verify(const zafe_key_t *ks,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[ZAFE_TAG_LEN]);

void forkskinny_zafe_encrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct);

void forkskinny_zafe_decrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg);

void forkskinny_zafe_encrypt_auth(const zafe_key_t *ks,
                                  const uint8_t *ad, size_t adlen,
                                  const uint8_t *msg, size_t mlen,
                                  uint8_t *ct,
                                  uint8_t tag[ZAFE_TAG_LEN]);

int forkskinny_zafe_decrypt_verify(const zafe_key_t *ks,
                                   const uint8_t *ad, size_t adlen,
                                   const uint8_t *ct, size_t clen,
                                   const uint8_t tag[ZAFE_TAG_LEN],
                                   uint8_t *msg);

#endif