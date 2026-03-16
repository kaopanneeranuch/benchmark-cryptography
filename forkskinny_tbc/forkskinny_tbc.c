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

/* fork_encrypt_full — alias of fork_encrypt for clarity in SonicAE */
void fork_encrypt_full(const uint8_t key[16],
                       const uint8_t tweak[16],
                       const uint8_t input[16],
                       uint8_t out_left[16],
                       uint8_t out_right[16])
{
    fork_encrypt(key, tweak, input, out_left, out_right);
}

/* fork_encrypt_right — reduced rounds, right output only
 * Used by: SuperSonic main loop
 *
 * ForkSkinny has a "forward-only" mode that computes only the right
 * branch using fewer rounds (ROUNDS_BEFORE + ROUNDS_AFTER instead of
 * ROUNDS_BEFORE + 2*ROUNDS_AFTER).
 * We pass NULL for the left output to signal right-only computation.
 */
void fork_encrypt_right(const uint8_t key[16],
                        const uint8_t tweak[16],
                        const uint8_t input[16],
                        uint8_t out_right[16])
{
    uint8_t tweakey[32];
    memcpy(tweakey,      tweak, 16);
    memcpy(tweakey + 16, key,   16);
    /* NULL left output → reference impl computes right branch only
     * with reduced round count                                      */
    forkskinny_128_256_encrypt(tweakey, NULL, out_right, input);
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