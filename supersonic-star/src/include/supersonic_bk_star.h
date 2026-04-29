#ifndef SUPERSONIC_BUTTERKNIFE_STAR_H
#define SUPERSONIC_BUTTERKNIFE_STAR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void supersonic_256_butterknife_deoxys(const uint8_t key[16],
                                       uint8_t out_left[16],
                                       uint8_t out_right[16],
                                       const uint8_t *message,
                                       uint32_t mlen);

void supersonic_256_butterknife_skinny(const uint8_t key[16],
                                       uint8_t out_left[16],
                                       uint8_t out_right[16],
                                       const uint8_t *message,
                                       uint32_t mlen);

void supersonic_256_butterknife_deoxys_opt(const uint8_t key[16],
                                           uint8_t out_left[16],
                                           uint8_t out_right[16],
                                           const uint8_t *message,
                                           uint32_t mlen);

/* Call counters */
void supersonic_bk_deoxys_reset_counters(void);
void supersonic_bk_deoxys_get_counters(uint32_t *oneleg, uint32_t *twoleg);
void supersonic_bk_deoxys_opt_reset_counters(void);
void supersonic_bk_deoxys_opt_get_counters(uint32_t *oneleg, uint32_t *twoleg);
void supersonic_bk_skinny_reset_counters(void);
void supersonic_bk_skinny_get_counters(uint32_t *oneleg, uint32_t *twoleg);

#ifdef __cplusplus
}
#endif

#endif