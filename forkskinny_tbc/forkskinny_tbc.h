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

void fork_encrypt_full(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t input[16],
                       uint8_t out_left[16],
                       uint8_t out_right[16]);

void fork_encrypt_left(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t input[16],
                       uint8_t out_left[16]);

/* Optional compatibility helper; not needed for paper-faithful SuperSonic */
void fork_encrypt_right(const uint8_t key[16],
                        const uint8_t tweak[16],
                        const uint8_t input[16],
                        uint8_t out_right[16]);

void fork_decrypt_left(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t ct_left[16],
                       uint8_t pt[16],
                       uint8_t out_right[16]);

#endif /* FORKSKINNY_TBC_H */