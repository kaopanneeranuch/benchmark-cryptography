#include "forkskinny_tbc.h"
#include "ForkAE/internal-forkskinny.h"
#include <string.h>

/* ── Tweakey layout for ForkSkinny-128-256 ──────────────────────
 *  tweakey[0..15]  = TK1 = tweak
 *  tweakey[16..31] = TK2 = key
 * ────────────────────────────────────────────────────────────── */

/* Standard encrypt — full rounds, both outputs
 * Used by: SAFE, ZAFE, and SuperSonic key expansion + finalization
 */
void fork_encrypt(const uint8_t key[16],
                  const uint8_t tweak[16],
                  const uint8_t input[16],
                  uint8_t c0[16],
                  uint8_t c1[16])
{
    uint8_t tweakey[32];
    memcpy(tweakey,      tweak, 16);   /* TK1 = tweak */
    memcpy(tweakey + 16, key,   16);   /* TK2 = key   */
    forkskinny_128_256_encrypt(tweakey, c0, c1, input);
}

/* Standard decrypt — recover plaintext from c0 (left ciphertext)
 * Used by: SAFE, ZAFE
 */
void fork_decrypt(const uint8_t key[16],
                  const uint8_t tweak[16],
                  const uint8_t ct[16],    /* c0 = left ciphertext in */
                  uint8_t       pt[16],    /* recovered plaintext out  */
                  uint8_t       c1[16])    /* right branch out         */
{
    uint8_t tweakey[32];
    memcpy(tweakey,      tweak, 16);
    memcpy(tweakey + 16, key,   16);
    forkskinny_128_256_decrypt(tweakey, pt, c1, ct);
}

/* Full forkcipher call: selector b */
void fork_encrypt_full(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t input[16],
                       uint8_t out_left[16],
                       uint8_t out_right[16])
{
    uint8_t tweakey[32];
    memcpy(tweakey,      tweak, 16);
    memcpy(tweakey + 16, key,   16);

    forkskinny_128_256_encrypt(tweakey, out_left, out_right, input);
}

/*
 * One-legged call for selector 0 = left output only.
 */
void fork_encrypt_left(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t input[16],
                       uint8_t out_left[16])
{
    uint8_t tweakey[32];
    uint8_t dummy_right[16];

    memcpy(tweakey,      tweak, 16);
    memcpy(tweakey + 16, key,   16);

    forkskinny_128_256_encrypt(tweakey, out_left, dummy_right, input);
}

void fork_encrypt_right(const uint8_t key[16],
                        const uint8_t tweak[16],
                        const uint8_t input[16],
                        uint8_t out_right[16])
{
    uint8_t tweakey[32];
    uint8_t dummy_left[16];

    memcpy(tweakey,      tweak, 16);
    memcpy(tweakey + 16, key,   16);

    forkskinny_128_256_encrypt(tweakey, dummy_left, out_right, input);
}

/* Decrypt from the left ciphertext branch */
void fork_decrypt_left(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t ct_left[16],
                       uint8_t pt[16],
                       uint8_t out_right[16])
{
    uint8_t tweakey[32];
    memcpy(tweakey,      tweak, 16);
    memcpy(tweakey + 16, key,   16);

    forkskinny_128_256_decrypt(tweakey, pt, out_right, ct_left);
}