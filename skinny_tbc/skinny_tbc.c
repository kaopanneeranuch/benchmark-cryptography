#include "skinny_tbc.h"
#include "SKINNY-AEAD/internal-skinny128.h"
#include <string.h>

/*
 * SKINNY-128-256: TK = tweak(16) || key(16) = 32 bytes
 * Using TK2 model: tweak in first 16 bytes, key in second 16 bytes.
 */

static skinny_128_256_key_schedule_t cached_ks;
static uint8_t cached_key[16];
static int cached_valid;

static void ensure_schedule_for_key(const uint8_t key[16])
{
    if (cached_valid && memcmp(cached_key, key, 16) == 0)
        return;

    uint8_t tk[32] = {0};
    memcpy(tk + 16, key, 16);
    skinny_128_256_init(&cached_ks, tk);
    memcpy(cached_key, key, 16);
    cached_valid = 1;
}

void skinny_encrypt(const uint8_t key[16], const uint8_t tweak[16],
                    const uint8_t in[16], uint8_t out[16])
{
    ensure_schedule_for_key(key);
    memcpy(cached_ks.TK1, tweak, 16);
    skinny_128_256_encrypt(&cached_ks, out, in);
}

void skinny_decrypt(const uint8_t key[16], const uint8_t tweak[16],
                    const uint8_t in[16], uint8_t out[16])
{
    ensure_schedule_for_key(key);
    memcpy(cached_ks.TK1, tweak, 16);
    skinny_128_256_decrypt(&cached_ks, out, in);
}