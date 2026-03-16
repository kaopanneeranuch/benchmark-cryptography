#ifndef SKINNY_OCB_H
#define SKINNY_OCB_H

#include <stdint.h>
#include <stddef.h>

#define OCB_KEY_LEN    16
#define OCB_NONCE_LEN  12
#define OCB_TAG_LEN    16
#define OCB_BLOCK_LEN  16

typedef struct {
    uint8_t key[OCB_KEY_LEN];
} ocb_key_t;

/* Key setup */
void skinny_ocb_keygen(const uint8_t key[OCB_KEY_LEN],
                       ocb_key_t *ks);

/* Full AEAD */
void skinny_ocb_encrypt_auth(const ocb_key_t *ks,
                             const uint8_t nonce[OCB_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[OCB_TAG_LEN]);

int  skinny_ocb_decrypt_verify(const ocb_key_t *ks,
                               const uint8_t nonce[OCB_NONCE_LEN],
                               const uint8_t *ad, size_t adlen,
                               const uint8_t *ct, size_t clen,
                               const uint8_t tag[OCB_TAG_LEN],
                               uint8_t *msg);

/* Split operations for benchmarking */
void skinny_ocb_hash(const ocb_key_t *ks,
                     const uint8_t nonce[OCB_NONCE_LEN],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *msg, size_t mlen,
                     uint8_t tag[OCB_TAG_LEN]);

void skinny_ocb_encrypt(const ocb_key_t *ks,
                        const uint8_t nonce[OCB_NONCE_LEN],
                        const uint8_t *msg, size_t mlen,
                        uint8_t *ct);

void skinny_ocb_decrypt(const ocb_key_t *ks,
                        const uint8_t nonce[OCB_NONCE_LEN],
                        const uint8_t *ct, size_t clen,
                        uint8_t *msg);

int  skinny_ocb_verify(const ocb_key_t *ks,
                       const uint8_t nonce[OCB_NONCE_LEN],
                       const uint8_t *ad, size_t adlen,
                       const uint8_t *msg, size_t mlen,
                       const uint8_t tag[OCB_TAG_LEN]);

#endif /* SKINNY_OCB_H */