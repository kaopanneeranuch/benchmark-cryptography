#ifndef SUPERSONIC_FS_STAR_H
#define SUPERSONIC_FS_STAR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void supersonic_256_star(const uint8_t key[16],
                         uint8_t out_left[16], uint8_t out_right[16],
                         const uint8_t *message, const uint32_t mlen);

void supersonic_384_star(const uint8_t key[16],
                         uint8_t out_left[16], uint8_t out_right[16],
                         const uint8_t *message, const uint32_t mlen);

void supersonic_192_star(const uint8_t key[16],
                         uint8_t out_left[8], uint8_t out_right[8],
                         const uint8_t *message, const uint32_t mlen);

/* Call counters */
void supersonic_fs_star_reset_counters(void);
void supersonic_fs256_star_get_counters(uint32_t *oneleg, uint32_t *twoleg);
void supersonic_fs384_star_get_counters(uint32_t *oneleg, uint32_t *twoleg);

#ifdef __cplusplus
}
#endif

#endif /* SUPERSONIC_STAR_H */
