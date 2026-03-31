#ifndef SKINNY_SCT_H
#define SKINNY_SCT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Paper-faithful SCT over a 128-bit-block tweakable cipher.
 *
 * Assumptions in the .c file:
 *   - block size = 16 bytes
 *   - nonce size = 16 bytes
 *   - tag size   = 16 bytes
 *
 * Change SCT_KEY_LEN to match your SKINNY backend.
 * The default below assumes a 128-bit key.
 */
#ifndef SCT_KEY_LEN
#define SCT_KEY_LEN   16
#endif

#define SCT_BLOCK_LEN 16
#define SCT_NONCE_LEN 16
#define SCT_TAG_LEN   16
#define SCT_IV_LEN    15

typedef struct {
    uint8_t key[SCT_KEY_LEN];
} sct_key_t;

void skinny_encrypt(const uint8_t *key,
                    const uint8_t tweak[16],
                    const uint8_t in[16],
                    uint8_t out[16]);


void skinny_sct_ctrt(const sct_key_t *ks,
                     const uint8_t nonce[SCT_NONCE_LEN],
                     const uint8_t iv_in[SCT_IV_LEN],
                     const uint8_t *in, size_t len,
                     uint8_t *out);

void skinny_sct_hash(const sct_key_t *ks,
                     const uint8_t nonce[SCT_NONCE_LEN],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *msg, size_t mlen,
                     uint8_t tag[SCT_TAG_LEN]);

int skinny_sct_verify(const sct_key_t *ks,
                      const uint8_t nonce[SCT_NONCE_LEN],
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *msg, size_t mlen,
                      const uint8_t tag[SCT_TAG_LEN]);

void skinny_sct_encrypt_auth(const sct_key_t *ks,
                             const uint8_t nonce[SCT_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[SCT_TAG_LEN]);

int skinny_sct_decrypt_verify(const sct_key_t *ks,
                              const uint8_t nonce[SCT_NONCE_LEN],
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *ct, size_t clen,
                              const uint8_t tag[SCT_TAG_LEN],
                              uint8_t *msg);

#endif