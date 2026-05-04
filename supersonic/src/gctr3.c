#include "include/gctr3.h"
#include "butterknife.h"
#include "internal-forkskinny.h"

#include <string.h>

/* ---- shared helpers ---------------------------------------------------- */

static void gctr3_xor_block(uint8_t out[GCTR3_N],
                             const uint8_t a[GCTR3_N],
                             const uint8_t b[GCTR3_N])
{
    for (size_t i = 0; i < GCTR3_N; ++i)
        out[i] = (uint8_t)(a[i] ^ b[i]);
}

static void gctr3_inc_be(uint8_t x[GCTR3_N])
{
    for (int i = (int)GCTR3_N - 1; i >= 0; --i) {
        x[i] = (uint8_t)(x[i] + 1u);
        if (x[i] != 0u)
            break;
    }
}

/* Force the two domain-separation bits to "10". */
static void gctr3_set_domain_10(uint8_t tweak[GCTR3_N])
{
    tweak[0] &= 0x3Fu;
    tweak[0] |= 0x80u;
}

/* ---- GCTR-3 / ForkSkinny ----------------------------------------------- */

/*
 * T_j = R xor <j>
 * X_j = N  (fixed for the whole message)
 */
void gctr_3_forkskinny(const uint8_t key[GCTR3_KEY_LEN],
                       const uint8_t R[GCTR3_N],
                       const uint8_t N[GCTR3_N],
                       const uint8_t *in, size_t len,
                       uint8_t *out)
{
    uint8_t tk[GCTR3_TWO_N];
    uint8_t j_enc[GCTR3_N];
    size_t offset = 0;

    memset(j_enc, 0, sizeof(j_enc));
    memcpy(tk + GCTR3_N, key, GCTR3_KEY_LEN);

    while (offset < len) {
        uint8_t stream[GCTR3_TWO_N];
        size_t remaining = len - offset;
        size_t take = remaining < GCTR3_TWO_N ? remaining : GCTR3_TWO_N;

        gctr3_inc_be(j_enc);
        gctr3_xor_block(tk, R, j_enc);

        if (remaining <= GCTR3_N)
            forkskinny_128_256_encrypt(tk, stream, NULL, N);
        else
            forkskinny_128_256_encrypt(tk, stream, stream + GCTR3_N, N);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}

void gctr_3_forkskinny_iv(const uint8_t key[GCTR3_KEY_LEN],
                          const uint8_t iv[GCTR3_TWO_N],
                          const uint8_t *in, size_t len,
                          uint8_t *out)
{
    gctr_3_forkskinny(key, iv, iv + GCTR3_N, in, len, out);
}

/* ---- GCTR-3 / Butterknife ---------------------------------------------- */

void gctr_3_butterknife(const uint8_t key[GCTR3_KEY_LEN],
                        const uint8_t R[GCTR3_N],
                        const uint8_t N[GCTR3_N],
                        const uint8_t *in, size_t len,
                        uint8_t *out,
                        uint8_t num_branches)
{
    uint8_t tweakey[GCTR3_TWO_N];
    uint8_t j_enc[GCTR3_N];
    uint8_t stream[GCTR3_N * GCTR3_BK_BRANCHES];
    size_t offset = 0u;

    if (num_branches == 0u || num_branches > GCTR3_BK_BRANCHES)
        return;

    memcpy(tweakey + GCTR3_N, key, GCTR3_KEY_LEN);
    memset(j_enc, 0, sizeof(j_enc));

    while (offset < len) {
        size_t remaining = len - offset;
        size_t b = (remaining + GCTR3_N - 1u) / GCTR3_N;
        if (b > num_branches)
            b = num_branches;
        size_t chunk = (size_t)GCTR3_N * (size_t)b;
        size_t take = remaining < chunk ? remaining : chunk;

        gctr3_inc_be(j_enc);
        gctr3_xor_block(tweakey, R, j_enc);

        butterknife_256_encrypt(tweakey, stream, N, (uint8_t)b);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}

void gctr_3_butterknife_iv(const uint8_t key[GCTR3_KEY_LEN],
                           const uint8_t iv[GCTR3_TWO_N],
                           const uint8_t *in, size_t len,
                           uint8_t *out,
                           uint8_t num_branches)
{
    gctr_3_butterknife(key, iv, iv + GCTR3_N, in, len, out, num_branches);
}

void gctr_3_butterknife_iv_full(const uint8_t key[GCTR3_KEY_LEN],
                                const uint8_t iv[GCTR3_TWO_N],
                                const uint8_t *in, size_t len,
                                uint8_t *out)
{
    gctr_3_butterknife_iv(key, iv, in, len, out, (uint8_t)GCTR3_BK_BRANCHES);
}

/* ---- GCTR-3' / ForkSkinny ---------------------------------------------- */

/*
 * T_j = (R xor <j>) with domain bits forced to "10"
 * X_j = N  (second n-bit half of tag)
 * tag = R || N  (32 bytes)
 */
void gctr_3_prime(const uint8_t *key,
                  const uint8_t tag[GCTR3_TWO_N],
                  const uint8_t *in, size_t len,
                  uint8_t *out)
{
    uint8_t tk[GCTR3_TWO_N];
    uint8_t j_enc[GCTR3_N];
    size_t offset = 0u;

    const uint8_t *R = tag;
    const uint8_t *N = tag + GCTR3_N;

    memset(j_enc, 0, sizeof(j_enc));
    memcpy(tk + GCTR3_N, key, GCTR3_KEY_LEN);

    while (offset < len) {
        uint8_t stream[GCTR3_TWO_N];
        size_t remaining = len - offset;
        size_t take = remaining < GCTR3_TWO_N ? remaining : GCTR3_TWO_N;

        gctr3_inc_be(j_enc);
        gctr3_xor_block(tk, R, j_enc);
        gctr3_set_domain_10(tk);

        if (remaining <= GCTR3_N)
            forkskinny_128_256_encrypt(tk, stream, NULL, N);
        else
            forkskinny_128_256_encrypt(tk, stream, stream + GCTR3_N, N);

        for (size_t j = 0; j < take; ++j)
            out[offset + j] = (uint8_t)(in[offset + j] ^ stream[j]);

        offset += take;
    }
}

/* ---- GCTR-3' / Butterknife --------------------------------------------- */

void gctr_3_prime_butterknife_rn(const uint8_t key[GCTR3_KEY_LEN],
                                 const uint8_t R[GCTR3_N],
                                 const uint8_t N[GCTR3_N],
                                 const uint8_t *in, size_t len,
                                 uint8_t *out)
{
    uint8_t tweakey[GCTR3_TWO_N];
    uint8_t j_enc[GCTR3_N];
    uint8_t stream[GCTR3_N * GCTR3_BK_BRANCHES];
    size_t offset = 0u;

    memset(j_enc, 0, sizeof(j_enc));
    memcpy(tweakey + GCTR3_N, key, GCTR3_KEY_LEN);

    while (offset < len) {
        size_t remaining = len - offset;
        size_t b = (remaining + GCTR3_N - 1u) / GCTR3_N;
        if (b > GCTR3_BK_BRANCHES)
            b = GCTR3_BK_BRANCHES;
        size_t chunk = (size_t)GCTR3_N * (size_t)b;
        size_t take = remaining < chunk ? remaining : chunk;

        gctr3_inc_be(j_enc);
        gctr3_xor_block(tweakey, R, j_enc);
        gctr3_set_domain_10(tweakey);

        butterknife_256_encrypt(tweakey, stream, N, (uint8_t)b);

        for (size_t i = 0; i < take; ++i)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);

        offset += take;
    }
}

void gctr_3_prime_butterknife(const uint8_t key[GCTR3_KEY_LEN],
                              const uint8_t tag[GCTR3_TWO_N],
                              const uint8_t *in, size_t len,
                              uint8_t *out)
{
    gctr_3_prime_butterknife_rn(key, tag, tag + GCTR3_N, in, len, out);
}
