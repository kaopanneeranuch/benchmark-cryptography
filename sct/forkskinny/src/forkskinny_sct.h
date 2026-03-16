#ifndef FORKSKINNY_SCT_H
#define FORKSKINNY_SCT_H

#include <stddef.h>
#include <stdint.h>

void forkskinny_sct_encrypt(const uint8_t key[16],
                           const uint8_t nonce[12],
                           const uint8_t *msg, size_t mlen,
                           uint8_t *ct, uint8_t tag[16]);

int forkskinny_sct_decrypt(const uint8_t key[16],
                          const uint8_t nonce[12],
                          const uint8_t *ct, size_t clen,
                          const uint8_t tag[16],
                          uint8_t *msg);

#endif /* FORKSKINNY_SCT_H */
