#include "skinny_gcm.h"
#include "ghash.h"
#include "SKINNY-AEAD/internal-skinny128.h"
#include <string.h>

static void inc_be32(uint8_t ctr[16]) { for (int i = 15; i >= 12; i--) if (++ctr[i]) break; }

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

static void build_tk(uint8_t tk[32], const uint8_t key[16])
{
    memset(tk, 0, 16);
    memcpy(tk + 16, key, 16);
}

void skinny_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t tk[32];
    build_tk(tk, key);
    skinny_128_256_encrypt_tk_full(tk, out, in);
}

void skinny_ctr_encrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *pt, size_t len, uint8_t *ct)
{
    uint8_t tk[32];
    build_tk(tk, key);

    uint8_t ctr[16];
    memset(ctr, 0, 16);
    memcpy(ctr, nonce, 12);
    ctr[15] = 1;

    uint8_t keystream[16];
    size_t off = 0;
    while (off < len) {
        inc_be32(ctr);
        skinny_128_256_encrypt_tk_full(tk, keystream, ctr);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            ct[off + i] = pt[off + i] ^ keystream[i];
        off += chunk;
    }
}

void skinny_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t len,
                       uint8_t *ct, uint8_t tag[16])
{
    uint8_t tk[32];
    build_tk(tk, key);

    uint8_t zero[16] = {0};
    uint8_t H[16];
    skinny_128_256_encrypt_tk_full(tk, H, zero);

    uint8_t J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, 12);
    J0[15] = 1;

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0;
    uint8_t keystream[16];
    while (off < len) {
        inc_be32(ctr);
        skinny_128_256_encrypt_tk_full(tk, keystream, ctr);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            ct[off + i] = pt[off + i] ^ keystream[i];
        off += chunk;
    }

    uint8_t S[16];
    ghash(H, aad, aad_len, ct, len, S);

    uint8_t EkJ0[16];
    skinny_128_256_encrypt_tk_full(tk, EkJ0, J0);
    for (int i = 0; i < 16; ++i)
        tag[i] = EkJ0[i] ^ S[i];
}

int skinny_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t len,
                      const uint8_t tag[16], uint8_t *pt)
{
    uint8_t tk[32];
    build_tk(tk, key);

    uint8_t zero[16] = {0};
    uint8_t H[16];
    skinny_128_256_encrypt_tk_full(tk, H, zero);

    uint8_t J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, 12);
    J0[15] = 1;

    uint8_t S[16];
    ghash(H, aad, aad_len, ct, len, S);

    uint8_t EkJ0[16];
    skinny_128_256_encrypt_tk_full(tk, EkJ0, J0);
    uint8_t expected[16];
    for (int i = 0; i < 16; ++i)
        expected[i] = EkJ0[i] ^ S[i];

    if (ct_memcmp(expected, tag, 16) != 0)
        return -1;

    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t off = 0;
    uint8_t keystream[16];
    while (off < len) {
        inc_be32(ctr);
        skinny_128_256_encrypt_tk_full(tk, keystream, ctr);
        size_t chunk = (len - off) < 16 ? (len - off) : 16;
        for (size_t i = 0; i < chunk; ++i)
            pt[off + i] = ct[off + i] ^ keystream[i];
        off += chunk;
    }

    return 0;
}

/* ----------------- Benchmark helpers ----------------- */
void skinny_gcm_keygen(const uint8_t key[16])
{
    // uint8_t tk[32];
    // build_tk(tk, key);
    // skinny_128_256_key_schedule_t ks;
    // skinny_128_256_init(&ks, tk);
    (void) key;
}

void skinny_gcm_compute_H(const uint8_t key[16], uint8_t H[16])
{
    uint8_t tk[32];
    build_tk(tk, key);
    uint8_t zero[16] = {0};
    skinny_128_256_encrypt_tk_full(tk, H, zero);
}

void skinny_gcm_compute_EkJ0(const uint8_t key[16], const uint8_t nonce[12], uint8_t out[16])
{
    uint8_t tk[32];
    build_tk(tk, key);
    uint8_t J0[16];
    memset(J0, 0, 16);
    memcpy(J0, nonce, 12);
    J0[15] = 1;
    skinny_128_256_encrypt_tk_full(tk, out, J0);
}