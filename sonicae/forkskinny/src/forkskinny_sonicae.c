#include "forkskinny_sonicae.h"
#include "forkskinny_tbc.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/*
 * ForkSkinny-128-256 instantiation:
 *   n = 128 bits
 *   t = 128 bits
 *   k = 128 bits
 *
 * Paper-oriented SuperSonic choice for ~100B-class messages:
 *   e = 4 bits
 *   e - 2 = 2 counter bits
 *   t - e = 124 bits
 *   block size = n + t + k - e = 380 bits
 *
 * This file now uses bit-level packing for SuperSonic.
 */

/* Public-size convenience */
#define SS_N_BYTES              16
#define SS_T_BYTES              16
#define SS_K_BYTES              16
#define SS_TAG_BYTES            32

/* Bit sizes */
#define SS_N_BITS               128u
#define SS_T_BITS               128u
#define SS_K_BITS               128u
#define SS_E_BITS               4u
#define SS_COUNTER_BITS         (SS_E_BITS - 2u)      /* 2 */
#define SS_T_MINUS_E_BITS       (SS_T_BITS - SS_E_BITS) /* 124 */
#define SS_T_MINUS_2_BITS       (SS_T_BITS - 2u)        /* 126 */
#define SS_BLOCK_BITS           (SS_N_BITS + SS_T_MINUS_E_BITS + SS_K_BITS) /* 380 */

#define SS_DS_LOOP              0x0u  /* 00 */
#define SS_DS_GCTR              0x2u  /* 10 */

#define SS_IPAD_ALIGNED         0x1u  /* 01 */
#define SS_IPAD_PADDED          0x3u  /* 11 */

/* Conservative practical limit for e=4 and i starting from 1: 1,2,3 fit in 2 bits */
#define SS_MAX_BLOCKS           3u

/* --------------------------------------------------------------------------
 * Bit helpers (MSB-first bit numbering inside each byte)
 * -------------------------------------------------------------------------- */

static uint8_t get_bit(const uint8_t *buf, size_t bitpos)
{
    const size_t bytepos = bitpos >> 3;
    const uint8_t mask = (uint8_t)(0x80u >> (bitpos & 7u));
    return (buf[bytepos] & mask) ? 1u : 0u;
}

static void set_bit(uint8_t *buf, size_t bitpos, uint8_t bit)
{
    const size_t bytepos = bitpos >> 3;
    const uint8_t mask = (uint8_t)(0x80u >> (bitpos & 7u));
    if (bit) {
        buf[bytepos] |= mask;
    } else {
        buf[bytepos] &= (uint8_t)~mask;
    }
}

static void copy_bits(uint8_t *dst, size_t dst_bitpos,
                      const uint8_t *src, size_t src_bitpos,
                      size_t nbits)
{
    for (size_t i = 0; i < nbits; i++) {
        set_bit(dst, dst_bitpos + i, get_bit(src, src_bitpos + i));
    }
}

static void xor_bits(uint8_t *dst, size_t dst_bitpos,
                     const uint8_t *src, size_t src_bitpos,
                     size_t nbits)
{
    for (size_t i = 0; i < nbits; i++) {
        if (get_bit(src, src_bitpos + i)) {
            const size_t p = dst_bitpos + i;
            const size_t bytepos = p >> 3;
            const uint8_t mask = (uint8_t)(0x80u >> (p & 7u));
            dst[bytepos] ^= mask;
        }
    }
}

static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

static size_t bits_to_bytes(size_t nbits)
{
    return (nbits + 7u) >> 3;
}

/* --------------------------------------------------------------------------
 * GF(2^128) doubling for Delta2
 * Polynomial: x^128 + x^7 + x^2 + x + 1
 * -------------------------------------------------------------------------- */

static void gf128_double(uint8_t x[SS_N_BYTES])
{
    uint8_t carry = (uint8_t)(x[0] >> 7);

    for (size_t i = 0; i < SS_N_BYTES - 1; i++) {
        x[i] = (uint8_t)((x[i] << 1) | (x[i + 1] >> 7));
    }

    x[SS_N_BYTES - 1] <<= 1;

    if (carry) {
        x[SS_N_BYTES - 1] ^= 0x87u;
    }
}

/* --------------------------------------------------------------------------
 * SuperSonic Pad(x, 0, M)
 * From the paper's Pad() definition with y = 0.
 * -------------------------------------------------------------------------- */

static size_t supersonic_padded_bits(size_t m_bits, uint8_t *ipad_bits)
{
    const size_t res = m_bits % SS_BLOCK_BITS;
    *ipad_bits = SS_IPAD_ALIGNED;

    if (res != 0u) {
        *ipad_bits = SS_IPAD_PADDED;
        return m_bits + 1u + (SS_BLOCK_BITS - 1u - res);
    }

    return m_bits;
}

/* --------------------------------------------------------------------------
 * Concrete injective encoding for SonicAE's (AD, PT)
 *
 * Choice here:
 *   Encode(AD, PT) = len(AD) as 64-bit big-endian || AD || PT
 *
 * This is injective, but it is an implementation choice, not fixed by the paper.
 * -------------------------------------------------------------------------- */

static void store_u64_be(uint8_t out[8], uint64_t x)
{
    out[0] = (uint8_t)(x >> 56);
    out[1] = (uint8_t)(x >> 48);
    out[2] = (uint8_t)(x >> 40);
    out[3] = (uint8_t)(x >> 32);
    out[4] = (uint8_t)(x >> 24);
    out[5] = (uint8_t)(x >> 16);
    out[6] = (uint8_t)(x >> 8);
    out[7] = (uint8_t)(x);
}

static uint8_t *build_injective_sonicae_input(const uint8_t *ad, size_t adlen,
                                              const uint8_t *pt, size_t ptlen,
                                              size_t *out_bits)
{
    const size_t enc_bytes = 8u + adlen + ptlen;
    uint8_t *enc = (uint8_t *)malloc(enc_bytes ? enc_bytes : 1u);
    if (!enc) {
        *out_bits = 0;
        return NULL;
    }

    store_u64_be(enc, (uint64_t)adlen);
    if (adlen) {
        memcpy(enc + 8u, ad, adlen);
    }
    if (ptlen) {
        memcpy(enc + 8u + adlen, pt, ptlen);
    }

    *out_bits = enc_bytes * 8u;
    return enc;
}

/* --------------------------------------------------------------------------
 * KDF placeholder: paper leaves Derive(K) abstract
 *
 * Default engineering choice:
 *   K1 <- left output of F_K(0^t, 0^n)
 *   K2 <- left output of F_K(0^t, 0...01), truncated to t-2 bits
 *
 * Replace if you later obtain a project-specific or author-specific KDF.
 * -------------------------------------------------------------------------- */

static void sonicae_derive_subkeys(const uint8_t master[SS_K_BYTES],
                                   uint8_t K1[SS_K_BYTES],
                                   uint8_t K2[SS_T_BYTES])
{
    uint8_t zero_tweak[SS_T_BYTES] = {0};
    uint8_t zero_block[SS_N_BYTES] = {0};
    uint8_t tmp_left[SS_N_BYTES];
    uint8_t tmp_right[SS_N_BYTES];

    fork_encrypt_full(master, zero_tweak, zero_block, K1, tmp_right);

    memset(zero_block, 0, sizeof(zero_block));
    zero_block[SS_N_BYTES - 1] = 0x01u;
    fork_encrypt_full(master, zero_tweak, zero_block, tmp_left, tmp_right);

    memcpy(K2, tmp_left, SS_T_BYTES);

    /* K2 is only t-2 = 126 bits */
    set_bit(K2, 126u, 0u);
    set_bit(K2, 127u, 0u);
}

/* --------------------------------------------------------------------------
 * Tweak builders for SuperSonic
 * -------------------------------------------------------------------------- */

static void ss_build_loop_tweak(uint8_t tweak[SS_T_BYTES],
                                const uint8_t M1_124[SS_T_BYTES],
                                uint8_t ctr2,
                                uint8_t ds2)
{
    memset(tweak, 0, SS_T_BYTES);

    /* Bits 0..123 <- M_{3i-1} */
    copy_bits(tweak, 0u, M1_124, 0u, SS_T_MINUS_E_BITS);

    /* Bits 124..125 <- counter */
    set_bit(tweak, 124u, (uint8_t)((ctr2 >> 1) & 1u));
    set_bit(tweak, 125u, (uint8_t)(ctr2 & 1u));

    /* Bits 126..127 <- domain separation */
    set_bit(tweak, 126u, (uint8_t)((ds2 >> 1) & 1u));
    set_bit(tweak, 127u, (uint8_t)(ds2 & 1u));
}

static void ss_build_final_tweak(uint8_t tweak[SS_T_BYTES],
                                 const uint8_t delta1[SS_T_BYTES],
                                 uint8_t ipad2)
{
    memset(tweak, 0, SS_T_BYTES);

    /* Bits 0..125 <- Delta1 */
    copy_bits(tweak, 0u, delta1, 0u, SS_T_MINUS_2_BITS);

    /* Bits 126..127 <- I'_pad */
    set_bit(tweak, 126u, (uint8_t)((ipad2 >> 1) & 1u));
    set_bit(tweak, 127u, (uint8_t)(ipad2 & 1u));
}

static void xor_k2_into_tweak(uint8_t tweak[SS_T_BYTES], const uint8_t K2[SS_T_BYTES])
{
    xor_bits(tweak, 0u, K2, 0u, SS_T_MINUS_2_BITS);
}

/* --------------------------------------------------------------------------
 * SuperSonic MAC with e = 4, bit-packed 128|124|128 parsing
 * -------------------------------------------------------------------------- */

void forkskinny_sonicae_supersonic(const uint8_t  key[SS_K_BYTES],
                                   const uint8_t *ad,  size_t adlen,
                                   const uint8_t *msg, size_t mlen,
                                   uint8_t       *out_tag)
{
    uint8_t K1[SS_K_BYTES];
    uint8_t K2[SS_T_BYTES];

    uint8_t delta1[SS_T_BYTES] = {0};  /* effectively 126 bits used */
    uint8_t delta2[SS_N_BYTES] = {0};
    uint8_t delta3[SS_K_BYTES] = {0};

    uint8_t M0[SS_N_BYTES];
    uint8_t M1[SS_T_BYTES];            /* only first 124 bits used */
    uint8_t M2[SS_K_BYTES];

    uint8_t U[SS_N_BYTES];
    uint8_t loop_tweak[SS_T_BYTES];
    uint8_t final_tweak[SS_T_BYTES];
    uint8_t loop_key[SS_K_BYTES];

    uint8_t X[SS_N_BYTES];
    uint8_t Y[SS_N_BYTES];

    uint8_t *enc = NULL;
    uint8_t *stream = NULL;
    size_t enc_bits = 0;
    size_t padded_bits = 0;
    size_t padded_bytes = 0;
    size_t blocks = 0;
    uint8_t ipad_bits = SS_IPAD_ALIGNED;

    sonicae_derive_subkeys(key, K1, K2);

    enc = build_injective_sonicae_input(ad, adlen, msg, mlen, &enc_bits);
    if (!enc) {
        memset(out_tag, 0, SS_TAG_BYTES);
        return;
    }

    padded_bits = supersonic_padded_bits(enc_bits, &ipad_bits);
    padded_bytes = bits_to_bytes(padded_bits);
    blocks = padded_bits / SS_BLOCK_BITS;

    /* Conservative guard for e = 4 and loop indices starting from 1 */
    if (blocks == 0u || blocks > SS_MAX_BLOCKS) {
        memset(out_tag, 0, SS_TAG_BYTES);
        free(enc);
        return;
    }

    stream = (uint8_t *)calloc(padded_bytes ? padded_bytes : 1u, 1u);
    if (!stream) {
        memset(out_tag, 0, SS_TAG_BYTES);
        free(enc);
        return;
    }

    memcpy(stream, enc, bits_to_bytes(enc_bits));

    /* Append the SuperSonic Pad() "1" bit iff padding is needed */
    if (padded_bits != enc_bits) {
        set_bit(stream, enc_bits, 1u);
    }

    for (size_t i = 0; i < blocks; i++) {
        const size_t base = i * SS_BLOCK_BITS;

        memset(M0, 0, sizeof(M0));
        memset(M1, 0, sizeof(M1));
        memset(M2, 0, sizeof(M2));

        /* Pi = M_{3i-2} || M_{3i-1} || M_{3i} = 128 | 124 | 128 bits */
        copy_bits(M0, 0u, stream, base, SS_N_BITS);
        copy_bits(M1, 0u, stream, base + SS_N_BITS, SS_T_MINUS_E_BITS);
        copy_bits(M2, 0u, stream, base + SS_N_BITS + SS_T_MINUS_E_BITS, SS_K_BITS);

        /*
         * T = M_{3i-1} || <i>_{e-2} || 00
         * e-2 = 2 bits here.
         * With i starting at 1, valid loop counters are 1,2,3 for this file.
         */
        ss_build_loop_tweak(loop_tweak, M1, (uint8_t)(i + 1u), SS_DS_LOOP);
        xor_k2_into_tweak(loop_tweak, K2);

        memcpy(loop_key, K1, SS_K_BYTES);
        xor_into(loop_key, M2, SS_K_BYTES);

        /* F^{K2⊕T,0}_{K1⊕M3i}(M3i−2) */
        fork_encrypt_left(loop_key, loop_tweak, M0, U);

        /*
         * Delta1 <- (U xor Delta1) xor_{t-2} M3i-1
         * Here t-2 = 126 and M3i-1 has 124 bits,
         * so the last two prefix bits are xor with 0 and remain unchanged.
         */
        xor_into(delta1, U, SS_N_BYTES);
        xor_bits(delta1, 0u, M1, 0u, SS_T_MINUS_E_BITS);
        set_bit(delta1, 126u, 0u);
        set_bit(delta1, 127u, 0u);

        /* Delta2 <- 2 * (U xor Delta2) */
        xor_into(delta2, U, SS_N_BYTES);
        gf128_double(delta2);

        /* Delta3 <- M3i xor Delta3 */
        xor_into(delta3, M2, SS_K_BYTES);
    }

    /* T <- Delta1 || I'_pad */
    ss_build_final_tweak(final_tweak, delta1, ipad_bits);
    xor_k2_into_tweak(final_tweak, K2);

    /* X, Y <- F^{K2⊕T,b}_{K1⊕Delta3}(Delta2) */
    memcpy(loop_key, K1, SS_K_BYTES);
    xor_into(loop_key, delta3, SS_K_BYTES);

    fork_encrypt_full(loop_key, final_tweak, delta2, X, Y);

    memcpy(out_tag, X, SS_N_BYTES);
    memcpy(out_tag + SS_N_BYTES, Y, SS_N_BYTES);

    free(stream);
    free(enc);
}

/* --------------------------------------------------------------------------
 * GCTR'2-3 (kept in the same shape as your existing implementation)
 * -------------------------------------------------------------------------- */

static void gctr_crypt(const uint8_t  key[SS_K_BYTES],
                       const uint8_t  N[SS_N_BYTES],
                       const uint8_t  R[SS_N_BYTES],
                       const uint8_t *in,
                       size_t         len,
                       uint8_t       *out)
{
    if (len == 0u) {
        return;
    }

    uint8_t tweak[SS_N_BYTES];
    uint8_t s0[SS_N_BYTES], s1[SS_N_BYTES];
    uint32_t j = 1u;

    size_t remaining = len;
    const uint8_t *src = in;
    uint8_t *dst = out;

    while (remaining > 0u) {
        memcpy(tweak, R, SS_N_BYTES);
        tweak[SS_N_BYTES - 4] ^= (uint8_t)(j >> 24);
        tweak[SS_N_BYTES - 3] ^= (uint8_t)(j >> 16);
        tweak[SS_N_BYTES - 2] ^= (uint8_t)(j >> 8);
        tweak[SS_N_BYTES - 1] ^= (uint8_t)(j);
        tweak[SS_N_BYTES - 1] = (uint8_t)((tweak[SS_N_BYTES - 1] & 0xFCu) | SS_DS_GCTR);

        fork_encrypt_full(key, tweak, N, s0, s1);

        size_t take = (remaining >= SS_N_BYTES) ? SS_N_BYTES : remaining;
        for (size_t i = 0; i < take; i++) {
            dst[i] = (uint8_t)(src[i] ^ s0[i]);
        }
        src += take;
        dst += take;
        remaining -= take;

        if (remaining > 0u) {
            take = (remaining >= SS_N_BYTES) ? SS_N_BYTES : remaining;
            for (size_t i = 0; i < take; i++) {
                dst[i] = (uint8_t)(src[i] ^ s1[i]);
            }
            src += take;
            dst += take;
            remaining -= take;
        }

        j++;
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void forkskinny_sonicae_keygen(const uint8_t key[SONICAE_KEY_LEN],
                               sonicae_key_t *ks)
{
    memcpy(ks->key, key, SONICAE_KEY_LEN);
}

void forkskinny_sonicae_auth(const sonicae_key_t *ks,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *pt, size_t ptlen,
                             uint8_t *tag)
{
    forkskinny_sonicae_supersonic(ks->key, ad, adlen, pt, ptlen, tag);
}

void forkskinny_sonicae_encrypt(const sonicae_key_t *ks,
                                const uint8_t *tag,
                                const uint8_t *pt, size_t ptlen,
                                uint8_t *ct)
{
    const uint8_t *R = tag;
    const uint8_t *N = tag + SS_N_BYTES;
    gctr_crypt(ks->key, N, R, pt, ptlen, ct);
}

void forkskinny_sonicae_decrypt(const sonicae_key_t *ks,
                                const uint8_t *tag,
                                const uint8_t *ct, size_t ctlen,
                                uint8_t *pt)
{
    const uint8_t *R = tag;
    const uint8_t *N = tag + SS_N_BYTES;
    gctr_crypt(ks->key, N, R, ct, ctlen, pt);
}

int forkskinny_sonicae_verify(const sonicae_key_t *ks,
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *pt, size_t ptlen,
                              const uint8_t *tag)
{
    uint8_t tag_r[SS_TAG_BYTES];
    uint8_t diff = 0u;

    forkskinny_sonicae_supersonic(ks->key, ad, adlen, pt, ptlen, tag_r);

    for (size_t i = 0; i < SS_TAG_BYTES; i++) {
        diff |= (uint8_t)(tag_r[i] ^ tag[i]);
    }

    return (diff == 0u) ? 0 : -1;
}

void forkskinny_sonicae_encrypt_auth(const sonicae_key_t *ks,
                                     const uint8_t *ad, size_t adlen,
                                     const uint8_t *pt, size_t ptlen,
                                     uint8_t *ct,
                                     uint8_t *tag)
{
    forkskinny_sonicae_auth(ks, ad, adlen, pt, ptlen, tag);
    forkskinny_sonicae_encrypt(ks, tag, pt, ptlen, ct);
}

int forkskinny_sonicae_decrypt_verify(const sonicae_key_t *ks,
                                      const uint8_t *ad, size_t adlen,
                                      const uint8_t *ct, size_t ctlen,
                                      const uint8_t *tag,
                                      uint8_t *pt)
{
    forkskinny_sonicae_decrypt(ks, tag, ct, ctlen, pt);

    if (forkskinny_sonicae_verify(ks, ad, adlen, pt, ctlen, tag) != 0) {
        memset(pt, 0, ctlen);
        return -1;
    }

    return 0;
}