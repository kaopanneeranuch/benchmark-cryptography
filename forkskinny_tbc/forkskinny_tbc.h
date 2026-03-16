#ifndef FORKSKINNY_TBC_H
#define FORKSKINNY_TBC_H

#include <stdint.h>

/* Fork helper wrappers used by AEAD modes (produce both branches). */
void fork_encrypt(const uint8_t key[16],
                  const uint8_t tweak[16],
                  const uint8_t input[16],
                  uint8_t c0[16],
                  uint8_t c1[16]);

void fork_decrypt(const uint8_t key[16],
                  const uint8_t tweak[16],
                  const uint8_t c0[16],
                  uint8_t m[16],
                  uint8_t c1[16]);

#endif /* FORKSKINNY_TBC_H */