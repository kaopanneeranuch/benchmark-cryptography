#ifndef BUTTERKNIFE_ZAFE_H
#define BUTTERKNIFE_ZAFE_H

#include <stddef.h>
#include <stdint.h>

/* 1-branch TBC primitive */
void butterknife_tbc(const uint8_t key[16], const uint8_t tweak[16],
                    const uint8_t in[16], uint8_t out[16]);

/* ZAFE mode: encrypt/decrypt */
void butterknife_zafe_encrypt(const uint8_t key[16],
                             const uint8_t nonce[12],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct, uint8_t tag[16]);

int butterknife_zafe_decrypt(const uint8_t key[16],
                            const uint8_t nonce[12],
                            const uint8_t *ct, size_t clen,
                            const uint8_t tag[16],
                            uint8_t *msg);

#endif /* BUTTERKNIFE_ZAFE_H */
