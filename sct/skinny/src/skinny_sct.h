#ifndef SKINNY_SCT_H
#define SKINNY_SCT_H

#include <stdint.h>
#include <stddef.h>

#define SCT_KEY_LEN    16
#define SCT_NONCE_LEN  12
#define SCT_TAG_LEN    16
#define SCT_BLOCK_LEN  16

typedef struct {
    uint8_t key[SCT_KEY_LEN];
} sct_key_t;

/* Key setup */
void skinny_sct_keygen(const uint8_t key[SCT_KEY_LEN],
                       sct_key_t *ks);

/* Full AEAD */
void skinny_sct_encrypt_auth(const sct_key_t *ks,
                             const uint8_t nonce[SCT_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[SCT_TAG_LEN]);

int  skinny_sct_decrypt_verify(const sct_key_t *ks,
                               const uint8_t nonce[SCT_NONCE_LEN],
                               const uint8_t *ad, size_t adlen,
                               const uint8_t *ct, size_t clen,
                               const uint8_t tag[SCT_TAG_LEN],
                               uint8_t *msg);

/* Split operations for benchmarking */
void skinny_sct_hash(const sct_key_t *ks,
                     const uint8_t nonce[SCT_NONCE_LEN],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *msg, size_t mlen,
                     uint8_t tag[SCT_TAG_LEN]);

void skinny_sct_encrypt(const sct_key_t *ks,
                        const uint8_t tag[SCT_TAG_LEN],
                        const uint8_t *msg, size_t mlen,
                        uint8_t *ct);

void skinny_sct_decrypt(const sct_key_t *ks,
                        const uint8_t tag[SCT_TAG_LEN],
                        const uint8_t *ct, size_t clen,
                        uint8_t *msg);

int  skinny_sct_verify(const sct_key_t *ks,
                       const uint8_t nonce[SCT_NONCE_LEN],
                       const uint8_t *ad, size_t adlen,
                       const uint8_t *msg, size_t mlen,
                       const uint8_t tag[SCT_TAG_LEN]);

#endif /* SKINNY_SCT_H */