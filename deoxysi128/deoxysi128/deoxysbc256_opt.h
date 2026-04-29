#ifndef DEOXYSBC256_OPT_H
#define DEOXYSBC256_OPT_H

#include <stdint.h>

/*
 * Deoxys-BC-256 optimized implementation.
 *
 * Deoxys-BC-256: 128-bit block, 256-bit tweakey (TK1||TK2, each 128 bits), 14 rounds.
 * No decryption, no BC-384 code paths.
 *
 * Two APIs:
 *
 * 1. Precomputed-TK1 API — use when TK1 (key half of the tweakey) is fixed across
 *    multiple encryptions but TK2 (tweak half) changes per call.
 *    Call deoxysbc256_precompute_tk1() once, then deoxysbc256_encrypt() per block.
 *
 * 2. Full-tweakey API — use when the full 32-byte tweakey changes on every call
 *    (e.g., SUPERSONIC where TK1 carries message-dependent data).
 *    deoxysbc256_encrypt_full() is BC-256-only: no tweakey_size branch, no BC-384
 *    code, allowing the compiler to generate tighter code than the reference.
 */

/* 15 sub-tweakey blocks (rounds 0..14), 4 words each */
#define DEOXYSBC256_RTK_WORDS  (4 * 15)

typedef struct {
    uint32_t rtk1[DEOXYSBC256_RTK_WORDS]; /* TK1 contribution + rcon, precomputed */
} deoxysbc256_ctx_t;

/* Precompute TK1's sub-tweakey schedule (H^r o G2^r applied to tk1, XOR rcon). */
void deoxysbc256_precompute_tk1(deoxysbc256_ctx_t *ctx, const uint8_t tk1[16]);

/* Encrypt one block with precomputed TK1 and per-call TK2.
 * tk2 is expanded (H-only) on-the-fly and combined with ctx->rtk1. */
void deoxysbc256_encrypt(const deoxysbc256_ctx_t *ctx,
                         const uint8_t tk2[16],
                         const uint8_t pt[16],
                         uint8_t ct[16]);

/* Encrypt one block with a full 32-byte tweakey (TK1||TK2).
 * Key schedule is fused with encryption (no rk[] array on stack).
 * BC-256 only — no runtime branch on tweakey size. */
void deoxysbc256_encrypt_full(const uint8_t tk[32],
                              const uint8_t pt[16],
                              uint8_t ct[16]);

#endif /* DEOXYSBC256_OPT_H */
