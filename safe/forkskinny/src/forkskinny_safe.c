#include "forkskinny_safe.h"
#include "forkskinny_tbc.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SAFE_N       16
#define SAFE_2N      32
#define SAFE_TAG_LEN 32

/* We instantiate SAFE with a 128-bit tweak and reserve 1 bit for domain
 * separation, leaving 127 bits for V.
 *
 * Bit convention used consistently in this file:
 *   tweak[0] bit 7  = domain bit b
 *   tweak[0] bits 6..0, tweak[1..15] = V (127 bits)
 */

/* ------------------------------------------------------------------------- */
/* helpers                                                                   */
/* ------------------------------------------------------------------------- */

static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] ^= src[i];
}

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = a[i] ^ b[i];
}

static void ct_memzero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

static int ct_memcmp_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* Big-endian 128-bit addition by a 32-bit counter */
static void be128_add_u32(uint8_t x[16], uint32_t add)
{
    int i = 15;
    uint32_t carry = add;

    while (i >= 0 && carry) {
        carry += x[i];
        x[i] = (uint8_t)carry;
        carry >>= 8;
        --i;
    }
}

/* 128-bit big-endian encoding of bit length */
static void encode_len128(uint8_t out[16], size_t bytes)
{
    uint64_t hi = 0;
    uint64_t lo = (uint64_t)bytes * 8ULL;

    out[0]  = (uint8_t)(hi >> 56);
    out[1]  = (uint8_t)(hi >> 48);
    out[2]  = (uint8_t)(hi >> 40);
    out[3]  = (uint8_t)(hi >> 32);
    out[4]  = (uint8_t)(hi >> 24);
    out[5]  = (uint8_t)(hi >> 16);
    out[6]  = (uint8_t)(hi >>  8);
    out[7]  = (uint8_t)(hi);

    out[8]  = (uint8_t)(lo >> 56);
    out[9]  = (uint8_t)(lo >> 48);
    out[10] = (uint8_t)(lo >> 40);
    out[11] = (uint8_t)(lo >> 32);
    out[12] = (uint8_t)(lo >> 24);
    out[13] = (uint8_t)(lo >> 16);
    out[14] = (uint8_t)(lo >>  8);
    out[15] = (uint8_t)(lo);
}

static void be128_rshift1(uint8_t x[16])
{
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t next_carry = (uint8_t)(x[i] & 1);
        x[i] = (uint8_t)((x[i] >> 1) | (carry << 7));
        carry = next_carry;
    }
}

static void split_u_v_255(const uint8_t s[32], uint8_t U[16], uint8_t V[16])
{
    memcpy(U, s, 16);
    memcpy(V, s + 16, 16);
    be128_rshift1(V);
}

/* ------------------------------------------------------------------------- */
/* tweak packing                                                             */
/* ------------------------------------------------------------------------- */

static void make_tweak_from_V(uint8_t tweak[16], uint8_t domain_bit,
                              const uint8_t V[16])
{
    memcpy(tweak, V, 16);
    tweak[0] &= 0x7F;                               /* clear domain bit slot   */
    tweak[0] |= (uint8_t)((domain_bit & 1) << 7);  /* set b || V convention   */
}

/* F_K^{b||V}(U) -> 2n bits = left || right */
static void tprf_eval_32(const uint8_t key[SAFE_KEY_LEN],
                         uint8_t domain_bit,
                         const uint8_t V[16],
                         const uint8_t U[16],
                         uint8_t out[32])
{
    uint8_t tweak[16];
    make_tweak_from_V(tweak, domain_bit, V);
    fork_encrypt_full(key, tweak, U, out, out + 16);
}

/* ------------------------------------------------------------------------- */
/* GF(2^256), reduction polynomial x^256 + x^10 + x^5 + x^2 + 1             */
/* ------------------------------------------------------------------------- */

static void gf256_shift_left_1(uint8_t x[32])
{
    uint8_t carry = 0;
    for (int i = 31; i >= 0; --i) {
        uint8_t next = (uint8_t)(x[i] >> 7);
        x[i] = (uint8_t)((x[i] << 1) | carry);
        carry = next;
    }
}

/* If the x^256 term appears, reduce with x^10 + x^5 + x^2 + 1.
 * Byte layout here is big-endian, with the least-significant polynomial
 * bits living in x[31].
 */
static void gf256_reduce_bit(uint8_t x[32])
{
    x[31] ^= 0x25; /* bits 5,2,0 */
    x[30] ^= 0x04; /* bit 10      */
}

static void gf256_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint8_t z[32] = {0};
    uint8_t v[32];

    memcpy(v, a, 32);

    for (size_t i = 0; i < 32; i++) {
        for (int bit = 7; bit >= 0; --bit) {
            if ((b[i] >> bit) & 1)
                xor_into(z, v, 32);

            {
                uint8_t msb = (uint8_t)(v[0] >> 7);
                gf256_shift_left_1(v);
                if (msb)
                    gf256_reduce_bit(v);
            }
        }
    }

    memcpy(out, z, 32);
}

/* ------------------------------------------------------------------------- */
/* SFMac block absorption                                                    */
/* ------------------------------------------------------------------------- */

static void sfmac_absorb_block(uint8_t T[32], const uint8_t L[32],
                               const uint8_t block[32])
{
    uint8_t tmp[32];
    xor_block(tmp, T, block, 32);
    gf256_mul(T, tmp, L);
}

static void sfmac_absorb_pad10(uint8_t T[32], const uint8_t L[32],
                               const uint8_t *data, size_t len)
{
    uint8_t block[32];
    size_t off = 0;

    while (len - off >= 32) {
        sfmac_absorb_block(T, L, data + off);
        off += 32;
    }

    /* Pad10 always adds one full block when input is already aligned */
    memset(block, 0, sizeof(block));
    if (len > off)
        memcpy(block, data + off, len - off);
    block[len - off] = 0x80;

    sfmac_absorb_block(T, L, block);
}

static void sfmac(const uint8_t key[SAFE_KEY_LEN],
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *msg, size_t mlen,
                  uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t zeroU[16] = {0};
    uint8_t zeroV[16] = {0};
    uint8_t L[32];
    uint8_t T[32] = {0};
    uint8_t block[32];
    uint8_t U[16];
    uint8_t V[16];
    uint8_t Y[32];

    /* L = [F_K^{0 || 0^t}(0^n)]_(2n) */
    tprf_eval_32(key, 0, zeroV, zeroU, L);

    /* X = Pad10(A) || Pad10(M) || <|A|>_n || <|M|>_n */
    sfmac_absorb_pad10(T, L, ad, adlen);
    sfmac_absorb_pad10(T, L, msg, mlen);

    encode_len128(block, adlen);
    encode_len128(block + 16, mlen);
    sfmac_absorb_block(T, L, block);

    split_u_v_255(T, U, V);

    /* Tag = [F_K^{0 || V}(U)]_lambda, lambda = 256 here */
    tprf_eval_32(key, 0, V, U, Y);
    memcpy(tag, Y, SAFE_TAG_LEN);

    ct_memzero(L, sizeof(L));
    ct_memzero(T, sizeof(T));
    ct_memzero(block, sizeof(block));
    ct_memzero(U, sizeof(U));
    ct_memzero(V, sizeof(V));
    ct_memzero(Y, sizeof(Y));
}

/* ------------------------------------------------------------------------- */
/* FEnc                                                                      */
/* ------------------------------------------------------------------------- */

static void fenc_crypt(const uint8_t key[SAFE_KEY_LEN],
                       const uint8_t iv[SAFE_TAG_LEN],
                       const uint8_t *in, size_t len,
                       uint8_t *out)
{
    uint8_t U[16];
    uint8_t V[16];
    size_t off = 0;
    uint32_t ctr = 0;

    split_u_v_255(iv, U, V);

    while (off < len) {
        uint8_t ctrU[16];
        uint8_t ks[32];
        size_t take = (len - off < 32) ? (len - off) : 32;

        memcpy(ctrU, U, 16);
        be128_add_u32(ctrU, ctr);

        /* keystream = F_K^{1 || V}(U + ctr) */
        tprf_eval_32(key, 1, V, ctrU, ks);

        for (size_t i = 0; i < take; i++)
            out[off + i] = in[off + i] ^ ks[i];

        off += take;
        ++ctr;

        ct_memzero(ctrU, sizeof(ctrU));
        ct_memzero(ks, sizeof(ks));
    }

    ct_memzero(U, sizeof(U));
    ct_memzero(V, sizeof(V));
}

/* ------------------------------------------------------------------------- */
/* public API                                                                */
/* ------------------------------------------------------------------------- */

void forkskinny_safe_keygen(const uint8_t key[SAFE_KEY_LEN], safe_key_t *ks)
{
    memcpy(ks->key, key, SAFE_KEY_LEN);
}

void forkskinny_safe_auth(const safe_key_t *ks,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[SAFE_TAG_LEN])
{
    sfmac(ks->key, ad, adlen, msg, mlen, tag);
}

int forkskinny_safe_verify(const safe_key_t *ks,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t computed[SAFE_TAG_LEN];
    sfmac(ks->key, ad, adlen, msg, mlen, computed);

    {
        int ok = ct_memcmp_eq(computed, tag, SAFE_TAG_LEN) ? 0 : -1;
        ct_memzero(computed, sizeof(computed));
        return ok;
    }
}

void forkskinny_safe_encrypt(const safe_key_t *ks,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[SAFE_TAG_LEN])
{
    sfmac(ks->key, ad, adlen, msg, mlen, tag);
    fenc_crypt(ks->key, tag, msg, mlen, ct);
}

int forkskinny_safe_decrypt(const safe_key_t *ks,
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *ct, size_t clen,
                            const uint8_t tag[SAFE_TAG_LEN],
                            uint8_t *msg)
{
    uint8_t computed[SAFE_TAG_LEN];

    fenc_crypt(ks->key, tag, ct, clen, msg);
    sfmac(ks->key, ad, adlen, msg, clen, computed);

    if (!ct_memcmp_eq(computed, tag, SAFE_TAG_LEN)) {
        ct_memzero(computed, sizeof(computed));
        ct_memzero(msg, clen);
        return -1;
    }

    ct_memzero(computed, sizeof(computed));
    return 0;
}

void forkskinny_safe_fenc_encrypt(const safe_key_t *ks,
                                  const uint8_t tag[SAFE_TAG_LEN],
                                  const uint8_t *pt, size_t ptlen,
                                  uint8_t *ct)
{
    fenc_crypt(ks->key, tag, pt, ptlen, ct);
}

void forkskinny_safe_fenc_decrypt(const safe_key_t *ks,
                                  const uint8_t tag[SAFE_TAG_LEN],
                                  const uint8_t *ct, size_t ctlen,
                                  uint8_t *pt)
{
    fenc_crypt(ks->key, tag, ct, ctlen, pt);
}