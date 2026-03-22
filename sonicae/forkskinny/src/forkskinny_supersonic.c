#include "forkskinny_supersonic.h"
#include "internal-forkskinny.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SS_N                 16u
#define SS_K                 16u
#define SS_T                 15u
#define SS_TK2               16u
#define SS_TAG               32u
#define SS_P_SIZE            47u
#define SS_CHUNK             (SS_P_SIZE - 1u)   /* 46 bytes processed per chunk */
#define SS_END_OF_MSG        0x80u
#define SS_COUNTER_BITS      12u
#define SS_COUNTER_MAX       ((1u << SS_COUNTER_BITS) - 1u)

typedef struct {
    uint8_t m[SS_N];
    uint8_t kt[SS_K + SS_T + 1u];
} ss_chains_t;

typedef struct {
    uint8_t P[SS_P_SIZE + 1u];
    uint8_t K_prime[SS_K];
    uint8_t mask[SS_N];
} ss_state_t;

static void ss_xor(uint8_t *dst, const uint8_t *src, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i)
        dst[i] ^= src[i];
}

/* Double in GF(2^128) using the same byte order as the reference code. */
static void ss_double_128(uint8_t x[SS_N])
{
    uint8_t carry;
    size_t i;

    carry = (uint8_t)((x[SS_N - 1u] >> 7) & 0x01u);
    for (i = 0; i < SS_N - 1u; ++i)
        x[i] = (uint8_t)((x[i] << 1) | ((x[i + 1u] >> 7) & 0x01u));
    x[SS_N - 1u] = (uint8_t)(x[SS_N - 1u] << 1);
    x[0] ^= (uint8_t)(0x87u * carry);
}

/* Two-branch ForkSkinny call: tk = key_part || tweak_part16. */
static void fs256_both(uint8_t out_left[SS_N],
                       uint8_t out_right[SS_N],
                       const uint8_t input[SS_N],
                       const uint8_t key_part[SS_K],
                       const uint8_t tweak_part[SS_TK2])
{
    uint8_t tk[SS_TAG];

    memcpy(tk, key_part, SS_K);
    memcpy(tk + SS_K, tweak_part, SS_TK2);
    forkskinny_128_256_encrypt(tk, out_left, out_right, input);
}

/*
 * One-legged ForkSkinny call for the normal SuperSonic round.
 *
 * The provided reference uses the right branch for the round update.
 * With the direct API, that means output_left = NULL and output_right = out.
 */
static void fs256_right_only(uint8_t out[SS_N],
                             const uint8_t input[SS_N],
                             const uint8_t key_part[SS_K],
                             const uint8_t tweak_part[SS_TK2])
{
    uint8_t tk[SS_TAG];

    memcpy(tk, key_part, SS_K);
    memcpy(tk + SS_K, tweak_part, SS_TK2);
    forkskinny_128_256_encrypt(tk, NULL, out, input);
}

static void ss_precompute(const uint8_t key[SS_K], ss_state_t *state)
{
    uint8_t zero_input[SS_N] = {0};
    uint8_t zero_tweak[SS_TK2] = {0};

    fs256_both(state->K_prime, state->mask, zero_input, key, zero_tweak);
}

static void ss_round(ss_state_t *state,
                     ss_chains_t *chains,
                     uint8_t buffer[SS_N],
                     uint16_t round_index)
{
    /* k-chain: xor M_{3i+1}. */
    ss_xor(chains->kt, state->P + SS_N, SS_K);

    /* Apply preprocessing masks. */
    ss_xor(state->P, state->mask, SS_N);
    ss_xor(state->P + SS_N, state->K_prime, SS_K);

    /* Counter occupies 12 bits, keeping the low nibble of P[47] free. */
    state->P[SS_P_SIZE - 1u] = (uint8_t)((round_index + 1u) & 0xffu);
    state->P[SS_P_SIZE]      = (uint8_t)(((round_index + 1u) & 0x0f00u) >> 4);

    /* Reduced round call: use the right branch only. */
    fs256_right_only(buffer, state->P, state->P + SS_N, state->P + SS_N + SS_K);

    /* m-chain update. */
    ss_xor(chains->m, buffer, SS_N);
    ss_double_128(chains->m);

    /* t-chain update over T = 15 bytes. */
    ss_xor(buffer, state->P + SS_N + SS_K, SS_T);
    ss_xor(chains->kt + SS_K, buffer, SS_T);
}

void supersonic_256_forkskinny(const uint8_t key[FORKSKINNY_SUPERSONIC_KEY_SIZE],
                               uint8_t out_left[FORKSKINNY_SUPERSONIC_BLOCK_SIZE],
                               uint8_t out_right[FORKSKINNY_SUPERSONIC_BLOCK_SIZE],
                               const uint8_t *message,
                               size_t message_len)
{
    ss_state_t state;
    ss_chains_t chains;
    uint8_t buffer[SS_N];
    size_t full_before_last;
    size_t final_len;
    uint8_t res_nonzero;
    size_t i;

    memset(&state, 0, sizeof(state));
    memset(&chains, 0, sizeof(chains));
    memset(buffer, 0, sizeof(buffer));

    ss_precompute(key, &state);

    /*
     * Match the reference structure safely:
     *   - process all but the last chunk in the loop,
     *   - then always process exactly one final chunk,
     *     padded when its length is < SS_CHUNK.
     */
    if (message_len == 0u) {
        full_before_last = 0u;
        final_len = 0u;
        res_nonzero = 0u;
    } else {
        final_len = message_len % SS_CHUNK;
        full_before_last = message_len / SS_CHUNK;
        if (final_len == 0u) {
            --full_before_last;
            final_len = SS_CHUNK;
            res_nonzero = 0u;
        } else {
            res_nonzero = 1u;
        }
    }

    if ((full_before_last + 1u) > SS_COUNTER_MAX) {
        memset(out_left, 0, SS_N);
        memset(out_right, 0, SS_N);
        return;
    }

    for (i = 0u; i < full_before_last; ++i) {
        memcpy(state.P, message + (i * SS_CHUNK), SS_CHUNK);
        ss_round(&state, &chains, buffer, (uint16_t)i);
    }

    /* Final chunk, with Sonic-style padding when short. */
    memset(state.P, 0, sizeof(state.P));
    if (final_len != 0u)
        memcpy(state.P, message + (full_before_last * SS_CHUNK), final_len);
    if (final_len < SS_CHUNK)
        state.P[final_len] = SS_END_OF_MSG;
    ss_round(&state, &chains, buffer, (uint16_t)full_before_last);

    /* Finalization. */
    chains.kt[SS_K + SS_T] = (uint8_t)(0x01u + (0x02u * res_nonzero));
    ss_xor(chains.kt, state.K_prime, SS_K);
    ss_xor(chains.m, state.mask, SS_N);
    fs256_both(out_left, out_right, chains.m, chains.kt, chains.kt + SS_K);
}

void forkskinny_supersonic_tag(const uint8_t key[FORKSKINNY_SUPERSONIC_KEY_SIZE],
                               const uint8_t *message,
                               size_t message_len,
                               uint8_t tag[FORKSKINNY_SUPERSONIC_TAG_SIZE])
{
    supersonic_256_forkskinny(key, tag, tag + SS_N, message, message_len);
}