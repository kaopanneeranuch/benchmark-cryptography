#ifndef FORKSKINNY_SONICAE_H
#define FORKSKINNY_SONICAE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Sonicae AEAD built on ForkSkinny-128-256.
 *
 * Key:   16 bytes (128 bits)
 * Nonce: 12 bytes (96 bits, padded to fill tweak)
 * Tag:   16 bytes (128 bits)
 *
 * The "keygen" step simply copies the key into an expanded-key
 * structure.  ForkSkinny does on-the-fly round-key derivation,
 * so keygen is lightweight; we keep it as a separate benchmarkable
 * step for measurement purposes.
 */

#define SONICAE_KEY_LEN    16
#define SONICAE_NONCE_LEN  12
#define SONICAE_TAG_LEN    32
#define SONICAE_BLOCK_LEN  16

/* Expanded key (trivial for ForkSkinny – just stores the raw key) */
typedef struct {
    uint8_t key[SONICAE_KEY_LEN];
} sonicae_key_t;

/*
 * Key expansion (keygen).
 * In ForkSkinny the raw key is used directly; this function copies
 * the key into the schedule structure so we can measure the step.
 */
void forkskinny_sonicae_keygen(const uint8_t key[SONICAE_KEY_LEN],
                               sonicae_key_t *ks);

/*
 * Encrypt plaintext (confidentiality only – no tag produced).
 * pt and ct may NOT overlap.  len may be any value (including non-block-aligned).
 * This implementation expects the 32-byte SuperSonic tag as input
 * (produced by `forkskinny_sonicae_auth`).
 */
void forkskinny_sonicae_encrypt(const sonicae_key_t *ks,
                                const uint8_t tag[],
                                const uint8_t *pt, size_t pt_len,
                                uint8_t *ct);

/*
 * Produce authentication tag over (ad, ct).
 * This uses the C1 fork branches that were produced during encryption
 * plus AD processing.  For benchmarking we recompute from scratch.
 */
void forkskinny_sonicae_auth(const sonicae_key_t *ks,
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t tag[]);

/*
 * Decrypt ciphertext (no tag check).
 * ct and pt may NOT overlap.
 * Returns 0 on success.
 */
void forkskinny_sonicae_decrypt(const sonicae_key_t *ks,
                               const uint8_t tag[],
                               const uint8_t *ct, size_t ct_len,
                               uint8_t *pt);

/*
 * Verify tag.  Recomputes the tag from (ad, ct) and compares.
 * Returns 0 if tag is valid, -1 otherwise.
 */
int forkskinny_sonicae_verify(const sonicae_key_t *ks,
                              const uint8_t *ad, size_t ad_len,
                              const uint8_t *pt, size_t pt_len,
                              const uint8_t tag[]);

void forkskinny_sonicae_encrypt_auth(const sonicae_key_t *ks,
                                     const uint8_t *ad, size_t ad_len,
                                     const uint8_t *pt, size_t pt_len,
                                     uint8_t *ct,
                                     uint8_t tag[]);

int forkskinny_sonicae_decrypt_verify(const sonicae_key_t *ks,
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *ct, size_t ct_len,
                                      const uint8_t tag[],
                                      uint8_t *pt);

#endif