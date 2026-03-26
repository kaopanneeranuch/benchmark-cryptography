#ifndef SUPERSONIC_BUTTERKNIFE_STAR_H
#define SUPERSONIC_BUTTERKNIFE_STAR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void supersonic_256_butterknife_deoxys_exact(const uint8_t key[16],
                                             uint8_t out_left[16],
                                             uint8_t out_right[16],
                                             const uint8_t *message,
                                             uint32_t mlen);

void supersonic_256_butterknife_star(const uint8_t key[16],
                                     uint8_t out_left[16],
                                     uint8_t out_right[16],
                                     const uint8_t *message,
                                     uint32_t mlen);

#ifdef __cplusplus
}
#endif

#endif