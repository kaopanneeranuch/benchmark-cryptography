#ifndef FORKSKINNY_SONICAE_H
#define FORKSKINNY_SONICAE_H

#include <stddef.h>
#include <stdint.h>

#define SONICAE_KEY_LEN  16u
#define SS_N_BYTES       16u
#define SS_TAG_BYTES     32u

typedef struct {
    uint8_t key[SONICAE_KEY_LEN];
} sonicae_key_t;

/* Key setup */
void forkskinny_sonicae_keygen(const uint8_t key[SONICAE_KEY_LEN],
                               sonicae_key_t *ks);

/* Authentication only: compute 32-byte SuperSonic tag */
void forkskinny_sonicae_auth(const sonicae_key_t *ks,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *pt, size_t ptlen,
                             uint8_t tag[SS_TAG_BYTES]);

/* Encryption/decryption using the provided 32-byte tag */
void forkskinny_sonicae_encrypt(const sonicae_key_t *ks,
                                const uint8_t tag[SS_TAG_BYTES],
                                const uint8_t *pt, size_t ptlen,
                                uint8_t *ct);

void forkskinny_sonicae_decrypt(const sonicae_key_t *ks,
                                const uint8_t tag[SS_TAG_BYTES],
                                const uint8_t *ct, size_t ctlen,
                                uint8_t *pt);

/* Recompute and verify the tag */
int forkskinny_sonicae_verify(const sonicae_key_t *ks,
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *pt, size_t ptlen,
                              const uint8_t tag[SS_TAG_BYTES]);

/* One-shot helpers */
void forkskinny_sonicae_encrypt_auth(const sonicae_key_t *ks,
                                     const uint8_t *ad, size_t adlen,
                                     const uint8_t *pt, size_t ptlen,
                                     uint8_t *ct,
                                     uint8_t tag[SS_TAG_BYTES]);

int forkskinny_sonicae_decrypt_verify(const sonicae_key_t *ks,
                                      const uint8_t *ad, size_t adlen,
                                      const uint8_t *ct, size_t ctlen,
                                      const uint8_t tag[SS_TAG_BYTES],
                                      uint8_t *pt);

#endif