#include "forkskinny_sonicae.h"
#include "forkskinny_tbc.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
 *  Constants
 *  ForkSkinny-128-256: n=128, k=128, t=128, e=2 bits
 *    SS_N     = 16 bytes  (n, FC block input size)
 *    SS_K     = 16 bytes  (k, key portion per block)
 *    SS_T     = 14 bytes  (t-e, tweak portion per block)
 *    SS_BLOCK = 46 bytes  (n+k+t-e, total per SuperSonic payload block)
 *    SS_TAG   = 32 bytes  (2n, full SuperSonic tag)
 *    SS_E_BITS = 2 bits   (reserved tweak bits)
 *    SS_T_FULL = 15 bytes (full tweak size, including e bits rounded to byte)
 * ═══════════════════════════════════════════════════════════════ */
#define SS_N         16
#define SS_K         16
#define SS_T         14             /* t-e bytes carried in message stream */
#define SS_E_BITS     2             /* e in bits */
#define SS_T_FULL    (SS_T + ((SS_E_BITS + 7)/8))  /* 14 + 1 = 15 bytes */
#define SS_PB        (SS_N + SS_K + SS_T)         /* 46 bytes payload per block */
#define SS_BLOCK     (SS_N + SS_K + SS_T_FULL)    /* 48 bytes total per block */
#define SS_TAG       32                         /* 2n bytes */
#define SONICS_END_OF_MESSAGE 0x80


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

static void pull_ad_msg(uint8_t *dst,
                        size_t len,
                        const uint8_t *ad,
                        size_t adlen,
                        size_t *ad_off,
                        const uint8_t *msg,
                        size_t mlen,
                        size_t *msg_off)
{
    size_t written = 0;
    while (written < len) {
        if (*ad_off < adlen) {
            size_t take = adlen - *ad_off;
            if (take > len - written)
                take = len - written;
            if (take > 0)
                memcpy(dst + written, ad + *ad_off, take);
            *ad_off += take;
            written += take;
        } else {
            size_t take = mlen - *msg_off;
            if (take > len - written)
                take = len - written;
            if (take > 0)
                memcpy(dst + written, msg + *msg_off, take);
            *msg_off += take;
            written += take;
        }
    }
}

void forkskinny_sonicae_supersonic(
        const uint8_t  key[SS_K],
        const uint8_t *ad,  size_t adlen,
        const uint8_t *msg, size_t mlen,
        uint8_t       *out_tag)
{
    uint8_t chain_k[SS_K] = {0};
    uint8_t chain_m[SS_N] = {0};
    uint8_t chain_t[SS_T_FULL] = {0};
    uint8_t fc_right[SS_N];

    const size_t total = adlen + mlen;
    const size_t res = total % SS_PB;
    const int res_flag = (res != 0) ? 1 : 0;
    const int numP = (total == 0) ? 0 : ((int)(total / SS_PB) - 1 + res_flag);

    size_t ad_off = 0;
    size_t msg_off = 0;

    // Process each full block
    for (int i = 0; i < numP; ++i) {
        uint8_t P[SS_BLOCK + 2] = {0};  // +2 for 12-bit block counter

        // Fill payload from AD || message
        pull_ad_msg(P, SS_PB, ad, adlen, &ad_off, msg, mlen, &msg_off);

        // Encode 12-bit block index
        P[SS_N + SS_K + SS_T]     = (uint8_t)((i + 1) & 0xFF);
        P[SS_N + SS_K + SS_T + 1] = (uint8_t)(((i + 1) >> 8) & 0x0F);

        // XOR key into the payload
        xor_into(P + SS_N, key, SS_K);

        // Prepare tweakey for ForkSkinny right branch
        uint8_t tweak_padded[16] = {0};
        memcpy(tweak_padded, P + SS_N, SS_T_FULL);

        fork_encrypt_right(key, tweak_padded, P, fc_right);

        // Update chains
        xor_into(chain_k, P + SS_N, SS_K);
        xor_into(chain_m, fc_right, SS_N);
        gf128_double(chain_m);

        uint8_t tbuf[SS_T_FULL];
        memcpy(tbuf, fc_right, SS_T_FULL);
        xor_into(tbuf, P + SS_N + SS_K, SS_T_FULL);
        xor_into(chain_t, tbuf, SS_T_FULL);
    }

    // Process final block (padding + domain separation)
    {
        uint8_t P[SS_BLOCK + 2] = {0};

        size_t last_len = (total == 0) ? 0 : (res_flag ? res : SS_PB);
        pull_ad_msg(P, last_len, ad, adlen, &ad_off, msg, mlen, &msg_off);

        if (res_flag)
            P[last_len] = SONICS_END_OF_MESSAGE; // padding byte

        const int last_idx = numP + 1;
        P[SS_N + SS_K + SS_T]     = (uint8_t)(last_idx & 0xFF);
        P[SS_N + SS_K + SS_T + 1] = (uint8_t)((last_idx >> 8) & 0x0F);

        xor_into(P + SS_N, key, SS_K);

        uint8_t tweak_padded[16] = {0};
        memcpy(tweak_padded, P + SS_N, SS_T_FULL);

        fork_encrypt_right(key, tweak_padded, P, fc_right);

        xor_into(chain_k, P + SS_N, SS_K);
        xor_into(chain_m, fc_right, SS_N);
        gf128_double(chain_m);

        uint8_t tbuf[SS_T_FULL];
        memcpy(tbuf, fc_right, SS_T_FULL);
        xor_into(tbuf, P + SS_N + SS_K, SS_T_FULL);
        xor_into(chain_t, tbuf, SS_T_FULL);

        // Domain separation: last 2 bits of tweak
        chain_t[SS_T_FULL - 1] &= 0xFC;
        chain_t[SS_T_FULL - 1] |= (0x01 + 0x02 * res_flag);
    }

    // Final XORs before ForkSkinny full encryption
    xor_into(chain_k, key, SS_K);

    uint8_t final_tweak[16] = {0};
    memcpy(final_tweak, chain_t, SS_T_FULL);

    // ForkSkinny full encryption to produce tag
    fork_encrypt_full(chain_k, final_tweak, chain_m, out_tag, out_tag + SS_N);
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

void forkskinny_sonicae_keygen(const uint8_t  key[SONICAE_KEY_LEN],
                                sonicae_key_t *ks)
{
    memcpy(ks->key, key, SONICAE_KEY_LEN);
}

void forkskinny_sonicae_auth(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *pt,   size_t ptlen,
    uint8_t             *tag)
{
    forkskinny_sonicae_supersonic(ks->key, ad, adlen, pt, ptlen, tag);
}

void forkskinny_sonicae_encrypt(
        const sonicae_key_t *ks,
    const uint8_t       *tag,
        const uint8_t       *pt,   size_t ptlen,
        uint8_t             *ct)
{
    const uint8_t *R = tag;          /* X = tag[0..15]  */
    const uint8_t *N = tag + SS_N;   /* Y = tag[16..31] */
    gctr_crypt(ks->key, N, R, pt, ptlen, ct);
}

void forkskinny_sonicae_decrypt(
        const sonicae_key_t *ks,
    const uint8_t       *tag,
        const uint8_t       *ct,   size_t ctlen,
        uint8_t             *pt)
{
    const uint8_t *R = tag;
    const uint8_t *N = tag + SS_N;
    gctr_crypt(ks->key, N, R, ct, ctlen, pt);
}

int forkskinny_sonicae_verify(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *pt,   size_t ptlen,
    const uint8_t       *tag)
{
    uint8_t tag_r[SS_TAG];
    forkskinny_sonicae_supersonic(ks->key, ad, adlen, pt, ptlen, tag_r);

    uint8_t diff = 0;
    for (int i = 0; i < SS_TAG; i++)
        diff |= tag_r[i] ^ tag[i];

    return (diff == 0) ? 0 : -1;
}

void forkskinny_sonicae_encrypt_auth(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *pt,   size_t ptlen,
        uint8_t             *ct,
    uint8_t             *tag)
{
    forkskinny_sonicae_auth(ks, ad, adlen, pt, ptlen, tag);
    forkskinny_sonicae_encrypt(ks, tag, pt, ptlen, ct);
}

int forkskinny_sonicae_decrypt_verify(
        const sonicae_key_t *ks,
        const uint8_t       *ad,   size_t adlen,
        const uint8_t       *ct,   size_t ctlen,
        const uint8_t       *tag,  uint8_t *pt)
{
    forkskinny_sonicae_decrypt(ks, tag, ct, ctlen, pt);
 
    if (forkskinny_sonicae_verify(ks, ad, adlen, pt, ctlen, tag) != 0) {
        memset(pt, 0, ctlen);
        return -1;
    }
    return 0;
}
 