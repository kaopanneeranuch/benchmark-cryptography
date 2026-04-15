#ifndef SUPERSONIC_H
#define SUPERSONIC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void supersonic_384_forkskinny(const uint8_t key[16],
                               uint8_t out_left[16], uint8_t out_right[16],
                               const uint8_t *message, const uint32_t mlen);

void supersonic_256_forkskinny(const uint8_t key[16],
                               uint8_t out_left[16], uint8_t out_right[16],
                               const uint8_t *message, const uint32_t mlen);

void supersonic_192_forkskinny(const uint8_t key[16],
                               uint8_t out_left[8], uint8_t out_right[8],
                               const uint8_t *message, const uint32_t mlen);

void supersonic_256_butterknife(const uint8_t key[16],
                                uint8_t out_left[16], uint8_t out_right[16],
                                const uint8_t *message, const uint32_t mlen);

/* butterknife variant call counters */
void supersonic_bk_reset_counters(void);
void supersonic_bk_get_counters(uint32_t *oneleg, uint32_t *twoleg);

#ifdef __cplusplus
}
#endif

#endif /* SUPERSONIC_H */
