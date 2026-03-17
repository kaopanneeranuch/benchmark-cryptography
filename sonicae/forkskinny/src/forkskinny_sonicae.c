#include "forkskinny_sonicae.h"
#include "forkskinny_tbc.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
 *  Constants
 *  ForkSkinny-128-256: n=128, k=128, t=128, e=4
 *    SS_N     = 16 bytes  (n, FC block input size)
 *    SS_K     = 16 bytes  (k, key portion per block)
 *    SS_T     = 12 bytes  (t-e, tweak portion per block)
 *    SS_BLOCK = 44 bytes  (n+k+t-e, total per SuperSonic block)
 *    SS_TAG   = 32 bytes  (2n, full SuperSonic tag)
 * ═══════════════════════════════════════════════════════════════ */
#define SS_N        16
#define SS_K        16
#define SS_T        12
#define SS_BLOCK   (SS_N + SS_K + SS_T)
#define SS_TAG      32

/* ═══════════════════════════════════════════════════════════════
 *  Internal helpers
 * ═══════════════════════════════════════════════════════════════ */

/* XOR src into dst in-place */
static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] ^= src[i];
}

/* GF(2^128) doubling — irreducible polynomial x^128+x^7+x^2+x+1 */
static void gf128_double(uint8_t x[SS_N])
{
    uint8_t msb = (x[0] >> 7) & 1;
    for (int i = 0; i < SS_N - 1; i++)
        x[i] = (uint8_t)((x[i] << 1) | (x[i + 1] >> 7));
    x[SS_N - 1] = (uint8_t)(x[SS_N - 1] << 1);
    x[0] ^= (uint8_t)(0x87 * msb);
}

/* ═══════════════════════════════════════════════════════════════
 *  SuperSonic MAC internals
 * ═══════════════════════════════════════════════════════════════ */

/* Key expansion: FC(K, 0^t, 0^n) → (K_prime, mask)
 *   K_prime = left  output → derived key  (XORed into key slot each round)
 *   mask    = right output → input mask   (XORed into block input each round)
 */
static void supersonic_key_expand(const uint8_t  key[SS_K],
                                   uint8_t        K_prime[SS_K],
                                   uint8_t        mask[SS_N])
{
    uint8_t zero_tweak[SS_K];
    uint8_t zero_input[SS_N];
    memset(zero_tweak, 0, sizeof(zero_tweak));
    memset(zero_input, 0, SS_N);
    fork_encrypt_full(key, zero_tweak, zero_input, K_prime, mask);
}

/* One SuperSonic main-loop round.
 *
 * Block layout (SS_BLOCK = 44 bytes):
 *   P[0      .. N-1      ] = M3i   → FC block input
 *   P[N      .. N+K-1    ] = M3i+1 → XORed into key slot
 *   P[N+K    .. N+K+T-1  ] = M3i+2 → XORed into tweak slot
 *
 * Three accumulators updated:
 *   chain_kt[0..K-1]   = XOR checksum of M3i+1  (k-chain)
 *   chain_m [0..N-1]   = doubling accumulation of FC right output (m-chain)
 *   chain_kt[K..K+T-1] = XOR of (FC_right XOR M3i+2)           (t-chain)
 *
 * FC call uses reduced rounds, right output only.
 */
static void supersonic_round(
        const uint8_t  K_prime[SS_K],
        const uint8_t  mask[SS_N],
        const uint8_t *P,
        uint8_t        chain_kt[SS_K + SS_T + 1],
        uint8_t        chain_m[SS_N],
        uint8_t        fc_right[SS_N],
        uint16_t       round_nr)
{
    const uint8_t *M3i   = P;
    const uint8_t *M3i_1 = P + SS_N;
    const uint8_t *M3i_2 = P + SS_N + SS_K;

    /* k-chain: accumulate key portion before FC call */
    xor_into(chain_kt, M3i_1, SS_K);

    /* Build FC inputs */
    uint8_t fc_input[SS_N];
    uint8_t fc_key  [SS_K];
    uint8_t fc_tweak[SS_K];
    memset(fc_tweak, 0, sizeof(fc_tweak));

    /* fc_input = M3i XOR mask */
    memcpy(fc_input, M3i, SS_N);
    xor_into(fc_input, mask, SS_N);

    /* fc_key = M3i+1 XOR K_prime */
    memcpy(fc_key, M3i_1, SS_K);
    xor_into(fc_key, K_prime, SS_K);

    /* fc_tweak[0..T-1] = M3i+2, counter in last bytes, last 4 bits = 0 */
    memcpy(fc_tweak, M3i_2, SS_T);
    fc_tweak[SS_T]     = (uint8_t)((round_nr + 1) & 0xff);
    fc_tweak[SS_T + 1] = (uint8_t)(((round_nr + 1) & 0x0f00) >> 4);

    /* FC: reduced rounds, right output only */
    fork_encrypt_right(fc_key, fc_tweak, fc_input, fc_right);

    /* m-chain: XOR fc_right then double in GF(2^128) */
    xor_into(chain_m, fc_right, SS_N);
    gf128_double(chain_m);

    /* t-chain: (fc_right XOR M3i+2) accumulated into chain_kt[K..K+T] */
    uint8_t t_contrib[SS_T];
    memcpy(t_contrib, fc_right, SS_T);
    xor_into(t_contrib, M3i_2, SS_T);
    xor_into(chain_kt + SS_K, t_contrib, SS_T);
}

/* ═══════════════════════════════════════════════════════════════
 *  SuperSonic MAC
 *
 *  Processes Pad(AD) ∥ Pad(M) as a single flat input.
 *  tag[0 ..N-1 ] = X  (left  output of final FC) → auth tag / R for GCTR
 *  tag[N ..2N-1] = Y  (right output of final FC) → nonce N for GCTR
 * ═══════════════════════════════════════════════════════════════ */
void forkskinny_sonicae_supersonic(
        const uint8_t  key[SS_K],
        const uint8_t *ad,  size_t adlen,
        const uint8_t *msg, size_t mlen,
        uint8_t        tag[SS_TAG])
{
    uint8_t K_prime[SS_K];
    uint8_t mask   [SS_N];
    supersonic_key_expand(key, K_prime, mask);

    uint8_t chain_m [SS_N];
    uint8_t chain_kt[SS_K + SS_K];
    uint8_t fc_right[SS_N];
    memset(chain_m,  0, SS_N);
    memset(chain_kt, 0, SS_K + SS_K);

    size_t   total     = adlen + mlen;
    size_t   ad_off    = 0;
    size_t   msg_off   = 0;
    size_t   remaining = total;
    uint16_t round_nr  = 0;

    while (remaining > 0) {
        uint8_t P[SS_BLOCK];
        size_t  chunk   = (remaining >= SS_BLOCK) ? SS_BLOCK : remaining;
        int     is_last = (chunk < SS_BLOCK) || (remaining == SS_BLOCK);

        /* Fill P sequentially from AD then MSG */
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

        /* 10* padding on last block if incomplete */
        if (is_last && chunk < SS_BLOCK) {
            P[chunk] = 0x80;
            memset(P + chunk + 1, 0, SS_BLOCK - chunk - 1);
        }

        supersonic_round(K_prime, mask, P,
                         chain_kt, chain_m, fc_right, round_nr);
        round_nr++;
        remaining -= chunk;
    }

    /* Finalization */
    /* padding indicator: 01 = no padding needed, 11 = padding was added */
    chain_kt[SS_K + SS_T] = ((total % SS_BLOCK) == 0) ? 0x01 : 0x03;

    xor_into(chain_kt, K_prime, SS_K);
    xor_into(chain_m,  mask,    SS_N);

    /* Final FC: full rounds, both outputs
     *   key   = chain_kt[0..K]
     *   tweak = chain_kt[K..K+T+1]
     *   input = chain_m
     */
    fork_encrypt_full(chain_kt,
                      chain_kt + SS_K,
                      chain_m,
                      tag,          /* X = left  output */
                      tag + SS_N);  /* Y = right output */
}

/* ═══════════════════════════════════════════════════════════════
 *  GCTR'2-3  (GCTR-3 with s=2, modified for SonicAE)
 *
 *  From [1] Table 2, GCTR-3:
 *    fX = N          → FC block input fixed to nonce per message
 *    fT = R ⊕ ⟨j⟩   → FC tweak = IV XOR counter
 *
 *  SonicAE modifications (Fig. 6 of Sonikku paper):
 *    N = tag[n+1..2n] = Y  (second half of SuperSonic tag)
 *    R = tag[1..n]    = X  (first  half of SuperSonic tag)
 *    last 2 tweak bits fixed to 10 (domain separation from MAC)
 *
 *  s=2: both FC outputs used as keystream → 2n bits per FC call
 *  CTR is symmetric: encrypt == decrypt
 * ═══════════════════════════════════════════════════════════════ */
static void gctr_crypt(const uint8_t  key[SS_K],
                       const uint8_t  N[SS_N],    /* Y = tag[n+1..2n] */
                       const uint8_t  R[SS_N],    /* X = tag[1..n]    */
                       const uint8_t *in,
                       size_t         len,
                       uint8_t       *out)
{
    if (len == 0) return;

    uint8_t  tweak[SS_N];
    uint8_t  s0[SS_N], s1[SS_N];
    uint32_t j = 1;                 /* counter starts at 1 */

    size_t        remaining = len;
    const uint8_t *src = in;
    uint8_t       *dst = out;

    while (remaining > 0) {
        /* Tj = R ⊕ ⟨j⟩, last 2 bits forced to 10 */
        memcpy(tweak, R, SS_N);
        tweak[SS_N - 4] ^= (uint8_t)(j >> 24);
        tweak[SS_N - 3] ^= (uint8_t)(j >> 16);
        tweak[SS_N - 2] ^= (uint8_t)(j >>  8);
        tweak[SS_N - 1] ^= (uint8_t)(j      );
        tweak[SS_N - 1]  = (tweak[SS_N - 1] & 0xFC) | 0x02;

        /* FC(K, Tj, N) → (s0, s1) — N is fixed per message */
        fork_encrypt_full(key, tweak, N, s0, s1);

        /* s0 → first n bits of keystream */
        size_t take = (remaining >= SS_N) ? SS_N : remaining;
        for (size_t i = 0; i < take; i++)
            dst[i] = src[i] ^ s0[i];
        src += take; dst += take; remaining -= take;

        /* s1 → next n bits of keystream */
        if (remaining > 0) {
            take = (remaining >= SS_N) ? SS_N : remaining;
            for (size_t i = 0; i < take; i++)
                dst[i] = src[i] ^ s1[i];
            src += take; dst += take; remaining -= take;
        }

        j++;
    }
}

/* ═══════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════ */

/* Key setup */
void forkskinny_sonicae_keygen(const uint8_t  key[SONICAE_KEY_LEN],
                                sonicae_key_t *ks)
{
    memcpy(ks->key, key, SONICAE_KEY_LEN);
}

/* ── Auth only ──────────────────────────────────────────────────
 *
 *  SuperSonic(K, Pad(AD) ∥ Pad(M)) → tag (32 bytes)
 *    tag[0..15]  = X = R  used as GCTR IV
 *    tag[16..31] = Y = N  used as GCTR nonce
 * ────────────────────────────────────────────────────────────── */
void forkskinny_sonicae_auth(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *pt,   size_t ptlen,
        uint8_t              tag[SS_TAG])
{
    forkskinny_sonicae_supersonic(ks->key, ad, adlen, pt, ptlen, tag);
}

/* ── Encrypt only ───────────────────────────────────────────────
 *
 *  GCTR'2-3(K, N=tag[16..31], R=tag[0..15], pt) → ct
 * ────────────────────────────────────────────────────────────── */
void forkskinny_sonicae_encrypt(
        const sonicae_key_t *ks,
        const uint8_t        tag[SS_TAG],
        const uint8_t       *pt,   size_t ptlen,
        uint8_t             *ct)
{
    const uint8_t *R = tag;          /* X = tag[0..15]  */
    const uint8_t *N = tag + SS_N;   /* Y = tag[16..31] */
    gctr_crypt(ks->key, N, R, pt, ptlen, ct);
}

/* ── Decrypt only ───────────────────────────────────────────────
 *
 *  CTR is symmetric — identical to encrypt.
 * ────────────────────────────────────────────────────────────── */
void forkskinny_sonicae_decrypt(
        const sonicae_key_t *ks,
        const uint8_t        tag[SS_TAG],
        const uint8_t       *ct,   size_t ctlen,
        uint8_t             *pt)
{
    const uint8_t *R = tag;
    const uint8_t *N = tag + SS_N;
    gctr_crypt(ks->key, N, R, ct, ctlen, pt);
}

/* ── Verify only ────────────────────────────────────────────────
 *
 *  Recomputes SuperSonic(K, Pad(AD) ∥ Pad(pt)) → tag'
 *  Constant-time compares tag' == received tag (full 32 bytes).
 *  Returns 0 on success, -1 on failure.
 * ────────────────────────────────────────────────────────────── */
int forkskinny_sonicae_verify(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *pt,   size_t ptlen,
        const uint8_t        tag[SS_TAG])
{
    uint8_t tag_r[SS_TAG];
    forkskinny_sonicae_supersonic(ks->key, ad, adlen, pt, ptlen, tag_r);

    uint8_t diff = 0;
    for (int i = 0; i < SS_TAG; i++)
        diff |= tag_r[i] ^ tag[i];

    return (diff == 0) ? 0 : -1;
}

/* ── Encrypt + Auth (combined) ──────────────────────────────────
 *
 *  Pass 1: SuperSonic(K, Pad(AD) ∥ Pad(pt)) → tag
 *  Pass 2: GCTR'2-3(K, N=tag[16..31], R=tag[0..15], pt) → ct
 *  Output: ct, tag (both 32-byte tag halves transmitted)
 * ────────────────────────────────────────────────────────────── */
void forkskinny_sonicae_encrypt_auth(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *pt,   size_t ptlen,
        uint8_t             *ct,
        uint8_t              tag[SS_TAG])
{
    forkskinny_sonicae_auth(ks, ad, adlen, pt, ptlen, tag);
    forkskinny_sonicae_encrypt(ks, tag, pt, ptlen, ct);
}

/* ── Decrypt + Verify (combined) ────────────────────────────────
 *
 *  Step 1: GCTR'2-3(K, N=tag[16..31], R=tag[0..15], ct) → pt
 *  Step 2: SuperSonic(K, Pad(AD) ∥ Pad(pt)) → tag'
 *  Step 3: Constant-time compare tag' == tag
 *  Step 4: Wipe pt on failure
 *  Returns 0 on success, -1 on failure.
 * ────────────────────────────────────────────────────────────── */
int forkskinny_sonicae_decrypt_verify(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *ct,   size_t ctlen,
        const uint8_t        tag[SS_TAG],
        uint8_t             *pt)
{
    forkskinny_sonicae_decrypt(ks, tag, ct, ctlen, pt);
 
    if (forkskinny_sonicae_verify(ks, ad, adlen, pt, ctlen, tag) != 0) {
        memset(pt, 0, ctlen);
        return -1;
    }
    return 0;
}
 