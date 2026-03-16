#include "forkskinny_sonicae.h"
#include "forkskinny_tbc.h"
#include <string.h>

#define SS_N        16          /* n in bytes                     */
#define SS_K        16          /* k in bytes                     */
#define SS_T        12          /* (t-e) in bytes, tweak portion  */
#define SS_BLOCK   (SS_N + SS_K + SS_T)   /* 44 bytes per block  */
#define SS_TAG      32          /* 2n-bit tag = 32 bytes          */

/* ── GF(2^128) doubling ─────────────────────────────────────── */
static void gf128_double(uint8_t x[SS_N])
{
    uint8_t msb = (x[0] >> 7) & 1;
    for (int i = 0; i < SS_N - 1; i++)
        x[i] = (uint8_t)((x[i] << 1) | (x[i+1] >> 7));
    x[SS_N-1] = (uint8_t)(x[SS_N-1] << 1);
    x[0] ^= (uint8_t)(0x87 * msb);   /* x^128 + x^7 + x^2 + x + 1 */
}

/* ── XOR helpers ────────────────────────────────────────────── */
static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++) dst[i] ^= src[i];
}

static void supersonic_key_expand(const uint8_t key[SS_K],
                                  uint8_t K_prime[SS_K],
                                  uint8_t mask[SS_N])
{
    uint8_t zero_tweak[SS_K + SS_T] ;
    uint8_t zero_input[SS_N];
    memset(zero_tweak,  0, sizeof(zero_tweak));
    memset(zero_input,  0, SS_N);
    /* Full-round FC, both outputs */
    fork_encrypt_full(key, zero_tweak, zero_input, K_prime, mask);
}

static void supersonic_round(
        const uint8_t K_prime[SS_K],
        const uint8_t mask[SS_N],
        const uint8_t *P,          /* SS_BLOCK bytes             */
        uint8_t chain_kt[SS_K + SS_T + 1],
        uint8_t chain_m[SS_N],
        uint8_t fc_right[SS_N],    /* scratch / output           */
        uint16_t round_nr)
{
    /* Split block into three parts */
    const uint8_t *M3i   = P;               /* FC block input   */
    const uint8_t *M3i_1 = P + SS_N;        /* key portion      */
    const uint8_t *M3i_2 = P + SS_N + SS_K; /* tweak portion    */

    /* k-chain: accumulate key portion BEFORE FC call */
    xor_into(chain_kt, M3i_1, SS_K);

    /* Build FC inputs */
    uint8_t fc_input[SS_N];
    uint8_t fc_key  [SS_K];
    uint8_t fc_tweak[SS_K + SS_T + 1];   /* full tweakey = K+T+counter */

    memcpy(fc_input, M3i,   SS_N);
    xor_into(fc_input, mask, SS_N);          /* fc_input = M3i XOR mask  */

    memcpy(fc_key, M3i_1, SS_K);
    xor_into(fc_key, K_prime, SS_K);         /* fc_key   = M3i+1 XOR K'  */

    memcpy(fc_tweak, M3i_2, SS_T);           /* fc_tweak[0..T-1] = M3i+2 */
    /* counter in last bytes of tweak, last 4 bits reserved = 0 */
    fc_tweak[SS_T]     = (uint8_t)((round_nr + 1) & 0xff);
    fc_tweak[SS_T + 1] = (uint8_t)(((round_nr + 1) & 0x0f00) >> 4);

    /* FC call: right output only (s=0 → left discarded) */
    fork_encrypt_right(fc_key, fc_tweak, fc_input, fc_right);

    /* m-chain: XOR fc_right then double */
    xor_into(chain_m, fc_right, SS_N);
    gf128_double(chain_m);

    /* t-chain: fc_right XOR M3i+2 → accumulate into chain_kt[K..K+T] */
    uint8_t t_contrib[SS_T];
    memcpy(t_contrib, fc_right, SS_T);
    xor_into(t_contrib, M3i_2, SS_T);
    xor_into(chain_kt + SS_K, t_contrib, SS_T);
}

void forkskinny_sonicae_supersonic(
        const uint8_t key[SS_K],
        const uint8_t *ad,  size_t adlen,
        const uint8_t *msg, size_t mlen,
        uint8_t tag[SS_TAG])
{
    /* ── key expansion ── */
    uint8_t K_prime[SS_K];
    uint8_t mask   [SS_N];
    supersonic_key_expand(key, K_prime, mask);

    /* ── chains init ── */
    uint8_t chain_m [SS_N];
    uint8_t chain_kt[SS_K + SS_T + 1];
    uint8_t fc_right[SS_N];
    memset(chain_m,  0, SS_N);
    memset(chain_kt, 0, SS_K + SS_T + 1);

    /* ── build flat input: AD || MSG ── */
    size_t  total  = adlen + mlen;
    /* process block by block without allocating the full concat buffer */

    uint16_t round_nr = 0;

    /* helper lambda — process one SS_BLOCK-sized chunk */
    /* We read from (ad, adlen, msg, mlen) sequentially */
    size_t ad_off  = 0;
    size_t msg_off = 0;
    size_t remaining = total;

    while (remaining > 0) {
        uint8_t P[SS_BLOCK];
        size_t  chunk = (remaining >= SS_BLOCK) ? SS_BLOCK : remaining;
        int     is_last = (chunk < SS_BLOCK) || (remaining == SS_BLOCK);

        /* fill P from AD then MSG sequentially */
        size_t filled = 0;
        while (filled < chunk) {
            if (ad_off < adlen) {
                size_t take = adlen - ad_off;
                if (take > chunk - filled) take = chunk - filled;
                memcpy(P + filled, ad + ad_off, take);
                ad_off  += take;
                filled  += take;
            } else {
                size_t take = mlen - msg_off;
                if (take > chunk - filled) take = chunk - filled;
                memcpy(P + filled, msg + msg_off, take);
                msg_off += take;
                filled  += take;
            }
        }

        /* padding for last block */
        if (is_last && chunk < SS_BLOCK) {
            P[chunk] = 0x80;                   /* 10* padding */
            memset(P + chunk + 1, 0, SS_BLOCK - chunk - 1);
        }

        supersonic_round(K_prime, mask, P, chain_kt, chain_m, fc_right, round_nr);
        round_nr++;
        remaining -= chunk;
    }

    /* ── finalization ── */
    /* padding indicator: 01 if total was multiple of SS_BLOCK, 11 otherwise */
    uint8_t i_pad = ((total % SS_BLOCK) == 0) ? 0x01 : 0x03;
    chain_kt[SS_K + SS_T] = i_pad;

    /* XOR K_prime into chain_kt[0..K] and mask into chain_m */
    xor_into(chain_kt, K_prime, SS_K);
    xor_into(chain_m,  mask,    SS_N);

    /* Final FC call: both outputs, full rounds */
    /* fc_key   = chain_kt[0..K]         */
    /* fc_tweak = chain_kt[K..K+T+1]     */
    /* fc_input = chain_m                */
    fork_encrypt_full(chain_kt,           /* key   */
                      chain_kt + SS_K,    /* tweak */
                      chain_m,            /* input */
                      tag,                /* X = left  output */
                      tag + SS_N);        /* Y = right output */
}

void forkskinny_sonicae_keygen(const uint8_t key[SONICAE_KEY_LEN],
                               sonicae_key_t *ks)
{
    memcpy(ks->key, key, SONICAE_KEY_LEN);
}