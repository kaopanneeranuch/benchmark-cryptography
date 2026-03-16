#include "forkskinny_tbc.h"
#include "ForkAE/internal-forkskinny.h"
#include <string.h>

/*
 * The reference ForkAE code provides:
 *   forkskinny_128_256_encrypt(...)
 *   forkskinny_128_256_decrypt(...)
 * with the state held in a ForkSkinnyState128_t structure.
 *
 * We adapt to the (key, tweak, in) → (c0, c1) interface.
 */

void fork_encrypt(const uint8_t key[16],
                         const uint8_t tweak[16],
                         const uint8_t input[16],
                         uint8_t c0[16],
                         uint8_t c1[16])
{
    uint8_t tweakey[32];
    memcpy(tweakey, tweak, 16);
    memcpy(tweakey + 16, key, 16);
    /* call reference implementation declared in internal-forkskinny.h */
    forkskinny_128_256_encrypt(tweakey, c0, c1, input);
}

void fork_decrypt(const uint8_t key[16],
                         const uint8_t tweak[16],
                         const uint8_t c0[16],
                         uint8_t m[16],
                         uint8_t c1[16])
{
    uint8_t tweakey[32];
    memcpy(tweakey, tweak, 16);
    memcpy(tweakey + 16, key, 16);
    forkskinny_128_256_decrypt(tweakey, m, c1, c0);
}