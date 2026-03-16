#ifndef BUTTERKNIFE_SAFE_H
#define BUTTERKNIFE_SAFE_H

#include <stddef.h>
#include <stdint.h>

/* 1-branch output (tag finalization) */
void butterknife_tbc(const uint8_t key[16], const uint8_t tweak[16],
                    const uint8_t in[16], uint8_t out[16]);

/* 2-branch output (encryption + auth in one call) */
void butterknife_tbc_fork(const uint8_t key[16], const uint8_t tweak[16],
                         const uint8_t in[16],
                         uint8_t out_b1[16], uint8_t out_b2[16]);

/* SAFE mode: encrypt/decrypt */
void butterknife_safe_encrypt(const uint8_t key[16],
                             const uint8_t nonce[12],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct, uint8_t tag[16]);

int butterknife_safe_decrypt(const uint8_t key[16],
                            const uint8_t nonce[12],
                            const uint8_t *ct, size_t clen,
                            const uint8_t tag[16],
                            uint8_t *msg);

#endif /* BUTTERKNIFE_SAFE_H */
