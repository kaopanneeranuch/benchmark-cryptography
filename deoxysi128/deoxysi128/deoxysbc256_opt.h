#ifndef DEOXYSBC256_OPT_H
#define DEOXYSBC256_OPT_H

#include <stdint.h>

/* 15 sub-tweakey blocks (rounds 0..14), 4 words each */
#define DEOXYSBC256_RTK_WORDS  (4 * 15)

typedef struct {
    uint32_t rtk1[DEOXYSBC256_RTK_WORDS];
} deoxysbc256_ctx_t;

void deoxysbc256_precompute_tk1(deoxysbc256_ctx_t *ctx, const uint8_t tk1[16]);

void deoxysbc256_encrypt(const deoxysbc256_ctx_t *ctx,
                         const uint8_t tk2[16],
                         const uint8_t pt[16],
                         uint8_t ct[16]);

void deoxysbc256_encrypt_full(const uint8_t tk[32],
                              const uint8_t pt[16],
                              uint8_t ct[16]);

#endif
