#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "forkskinny_tbc.h"
#include "forkskinny_zafe.h"

/* no nonce in these APIs anymore */

/* ------------------------------------------------------------------------- */
/* parameters                                                                */
/* ------------------------------------------------------------------------- */

#define ZAFE_INTERNAL_N          16
#define ZAFE_INTERNAL_2N         32
#define ZAFE_INTERNAL_TAG_LEN    32
#define ZAFE_INTERNAL_ENC_KEY    16
#define ZAFE_INTERNAL_MAC_KEY    16

/* ZMAC parameters for the ForkSkinny-adapted backend */
#define ZMAC_BS                  16
#define ZMAC_TS                  16
#define ZMAC_KS                  16
#define ZMAC_PBSIZE              (ZMAC_BS + ZMAC_TS - 1)   /* 31 bytes */

/* ------------------------------------------------------------------------- */
/* helpers                                                                   */
/* ------------------------------------------------------------------------- */

static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

static void xor_prefix(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

static void ct_memzero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

static int ct_memcmp_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

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
        uint8_t next_carry = (uint8_t)(x[i] & 1u);
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

static size_t pad10_len(size_t len, size_t blocksize)
{
    return ((len / blocksize) + 1u) * blocksize;
}

static size_t write_pad10(uint8_t *out, const uint8_t *in, size_t len, size_t blocksize)
{
    size_t plen = pad10_len(len, blocksize);
    memset(out, 0, plen);
    if (len) {
        memcpy(out, in, len);
    }
    out[len] = 0x80;
    return plen;
}

/* ------------------------------------------------------------------------- */
/* ForkSkinny-adapted TPRF for FEnc                                          */
/* ------------------------------------------------------------------------- */

/* tweak = b || V, where b is stored in tweak[0] bit 7 */
static void make_tweak_from_V(uint8_t tweak[16], uint8_t domain_bit,
                              const uint8_t V[16])
{
    memcpy(tweak, V, 16);
    tweak[0] &= 0x7F;
    tweak[0] |= (uint8_t)((domain_bit & 1u) << 7);
}

/* F_K^{b||V}(U) -> 32 bytes = left || right */
static void tprf_eval_32(const uint8_t key[ZAFE_INTERNAL_ENC_KEY],
                         uint8_t domain_bit,
                         const uint8_t V[16],
                         const uint8_t U[16],
                         uint8_t out[32])
{
    uint8_t tweak[16];
    make_tweak_from_V(tweak, domain_bit, V);
    fork_encrypt_full(key, tweak, U, out, out + 16);
    ct_memzero(tweak, sizeof(tweak));
}

/* ------------------------------------------------------------------------- */
/* FEnc                                                                      */
/* ------------------------------------------------------------------------- */

/*
 * Algorithm 4:
 *   IV <- [T]_{min(lambda, n+t)}
 *
 * Here lambda = 256 and n+t = 256, so IV is the full 32-byte tag.
 */
static void fenc_crypt(const uint8_t key[ZAFE_INTERNAL_ENC_KEY],
                       const uint8_t iv[ZAFE_INTERNAL_TAG_LEN],
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

        /* keystream = F_K^{1||V}(U + ctr) */
        tprf_eval_32(key, 1, V, ctrU, ks);

        for (size_t i = 0; i < take; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }

        off += take;
        ++ctr;

        ct_memzero(ctrU, sizeof(ctrU));
        ct_memzero(ks, sizeof(ks));
    }

    ct_memzero(U, sizeof(U));
    ct_memzero(V, sizeof(V));
}

/* ------------------------------------------------------------------------- */
/* ZMAC single-block primitive                                               */
/* ------------------------------------------------------------------------- */

/*
 * ForkSkinny adaptation:
 * use one fixed branch as the single-output block primitive E for ZMAC.
 * We choose the LEFT branch consistently.
 */
static void zmac_block_encrypt(const uint8_t key[16],
                               const uint8_t tweak[16],
                               const uint8_t input[16],
                               uint8_t output[16])
{
    uint8_t other[16];
    fork_encrypt_full(key, tweak, input, output, other);
    ct_memzero(other, sizeof(other));
}

/* ------------------------------------------------------------------------- */
/* ZMAC internals                                                            */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t key[16];
    uint8_t tweak[16];
    uint8_t message[16];
    uint8_t mask_l[16];
    uint8_t mask_r[16];
    uint8_t out[32];
} zmac_ctx_t;

typedef struct {
    uint8_t u[16];
    uint8_t v[16];
} zmac_chains_t;

static void arrLeftByOne(uint8_t *out, int len)
{
    for (int i = 0; i < len - 1; ++i) {
        out[i] = (uint8_t)((out[i] << 1) | ((out[i + 1] >> 7) & 1u));
    }
    out[len - 1] <<= 1;
}

static void arrMULT(uint8_t *out, uint8_t prpol, uint8_t len)
{
    uint8_t tmp = (uint8_t)((out[len - 1] >> 7) & 1u);
    arrLeftByOne(out, len);
    out[0] ^= (uint8_t)(prpol * tmp);
}

static void ZHASH(zmac_ctx_t *ctx, zmac_chains_t *chains, uint8_t prpol)
{
    uint8_t tmp[15];
    uint8_t cmask[16];

    memcpy(tmp, ctx->tweak, 15);

    xor_into(ctx->message, ctx->mask_l, 16);
    xor_prefix(ctx->tweak, ctx->mask_r, 15);

    ctx->tweak[15] = 0x08;
    zmac_block_encrypt(ctx->key, ctx->tweak, ctx->message, cmask);

    xor_into(chains->u, cmask, 16);
    arrMULT(chains->u, prpol, 16);

    xor_prefix(tmp, cmask, 15);
    xor_prefix(chains->v, tmp, 15);

    arrMULT(ctx->mask_l, prpol, 16);
    arrMULT(ctx->mask_r, prpol, 15);

    ct_memzero(tmp, sizeof(tmp));
    ct_memzero(cmask, sizeof(cmask));
}

static void ZFIN(zmac_ctx_t *ctx, uint8_t fin)
{
    uint8_t tmp[16];

    /* Y1 */
    ctx->tweak[15] = fin;
    zmac_block_encrypt(ctx->key, ctx->tweak, ctx->message, ctx->out);

    ++ctx->tweak[15];
    zmac_block_encrypt(ctx->key, ctx->tweak, ctx->message, tmp);
    xor_into(ctx->out, tmp, 16);

    /* Y2 */
    ++ctx->tweak[15];
    zmac_block_encrypt(ctx->key, ctx->tweak, ctx->message, ctx->out + 16);

    ++ctx->tweak[15];
    zmac_block_encrypt(ctx->key, ctx->tweak, ctx->message, tmp);
    xor_into(ctx->out + 16, tmp, 16);

    ct_memzero(tmp, sizeof(tmp));
}

/* ------------------------------------------------------------------------- */
/* ZMAC(K', X)                                                               */
/* ------------------------------------------------------------------------- */

static void zmac(const uint8_t mac_key[16],
                 const uint8_t *X, size_t xlen,
                 uint8_t tag[32])
{
    zmac_ctx_t ctx;
    zmac_chains_t chains;
    size_t off;
    uint8_t fin = 0;
    const uint8_t prpol = 0x87;

    memcpy(ctx.key, mac_key, 16);
    memset(ctx.tweak, 0, 16);
    memset(ctx.message, 0, 16);
    memset(ctx.mask_l, 0, 16);
    memset(ctx.mask_r, 0, 16);
    memset(ctx.out, 0, 32);
    memset(chains.u, 0, 16);
    memset(chains.v, 0, 16);

    /* mask_l */
    ctx.tweak[15] = 0x09;
    zmac_block_encrypt(ctx.key, ctx.tweak, ctx.message, ctx.mask_l);

    /* mask_r */
    memset(ctx.tweak, 0, 16);
    ctx.tweak[14] = 0x01;
    zmac_block_encrypt(ctx.key, ctx.tweak, ctx.message, ctx.mask_r);

    off = 0;
    while (xlen - off > ZMAC_PBSIZE) {
        memcpy(ctx.message, X + off, 16);
        memcpy(ctx.tweak, X + off + 16, 15);
        ctx.tweak[15] = 0;
        ZHASH(&ctx, &chains, prpol);
        off += ZMAC_PBSIZE;
    }

    {
        size_t rem = xlen - off;

        memset(ctx.message, 0, 16);
        memset(ctx.tweak, 0, 16);

        if (rem == ZMAC_PBSIZE) {
            memcpy(ctx.message, X + off, 16);
            memcpy(ctx.tweak, X + off + 16, 15);
            fin = 0;
        } else {
            if (rem >= 16) {
                memcpy(ctx.message, X + off, 16);
                rem -= 16;
                memcpy(ctx.tweak, X + off + 16, rem);
                ctx.tweak[rem] ^= 0x80;
            } else {
                memcpy(ctx.message, X + off, rem);
                ctx.message[rem] ^= 0x80;
            }
            fin = 4;
        }

        ZHASH(&ctx, &chains, prpol);
    }

    memcpy(ctx.tweak, chains.v, 16);
    memcpy(ctx.message, chains.u, 16);
    ZFIN(&ctx, fin);
    memcpy(tag, ctx.out, 32);

    ct_memzero(&ctx, sizeof(ctx));
    ct_memzero(&chains, sizeof(chains));
}

/* ------------------------------------------------------------------------- */
/* ZFMac(K', A, M)                                                           */
/* X = Pad10(A) || Pad10(M) || |A|_n || |M|_n                                */
/* ------------------------------------------------------------------------- */

static void zfmac(const uint8_t mac_key[16],
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *msg, size_t mlen,
                  uint8_t tag[32])
{
    uint8_t lenblk[32];
    uint8_t *X;
    size_t adp, mp, xlen, off;

    adp = pad10_len(adlen, ZMAC_PBSIZE);
    mp  = pad10_len(mlen,  ZMAC_PBSIZE);
    xlen = adp + mp + sizeof(lenblk);

    X = (uint8_t *)malloc(xlen ? xlen : 1u);
    if (!X) {
        memset(tag, 0, 32);
        return;
    }

    off = 0;
    off += write_pad10(X + off, ad, adlen, ZMAC_PBSIZE);
    off += write_pad10(X + off, msg, mlen, ZMAC_PBSIZE);

    encode_len128(lenblk, adlen);
    encode_len128(lenblk + 16, mlen);
    memcpy(X + off, lenblk, sizeof(lenblk));

    zmac(mac_key, X, xlen, tag);

    ct_memzero(lenblk, sizeof(lenblk));
    ct_memzero(X, xlen);
    free(X);
}

/* ------------------------------------------------------------------------- */
/* public API: paper-structured 2-key ZAFE                                   */
/* ------------------------------------------------------------------------- */

void forkskinny_zafe_keygen(const uint8_t key[ZAFE_KEY_LEN],
                            zafe_key_t *ks)
{
    memcpy(ks->enc_key, key, 16);
    memcpy(ks->mac_key, key + 16, 16);
}

void forkskinny_zafe_hash(const zafe_key_t *ks,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *msg, size_t mlen,
                          uint8_t tag[ZAFE_TAG_LEN])
{
    uint8_t full_tag[ZAFE_INTERNAL_TAG_LEN];
    zfmac(ks->mac_key, ad, adlen, msg, mlen, full_tag);
    memcpy(tag, full_tag, ZAFE_TAG_LEN);
    ct_memzero(full_tag, sizeof(full_tag));
}

int forkskinny_zafe_verify(const zafe_key_t *ks,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[ZAFE_TAG_LEN])
{
    uint8_t computed[ZAFE_TAG_LEN];
    forkskinny_zafe_hash(ks, ad, adlen, msg, mlen, computed);

    {
        int ok = ct_memcmp_eq(computed, tag, ZAFE_TAG_LEN) ? 0 : -1;
        ct_memzero(computed, sizeof(computed));
        return ok;
    }
}

void forkskinny_zafe_encrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct)
{
    /* IV = [T]_{min(lambda, n+t)} = full 32-byte tag here */
    fenc_crypt(ks->enc_key, tag, msg, mlen, ct);
}

void forkskinny_zafe_decrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg)
{
    fenc_crypt(ks->enc_key, tag, ct, clen, msg);
}

void forkskinny_zafe_encrypt_auth(const zafe_key_t *ks,
                                  const uint8_t *ad, size_t adlen,
                                  const uint8_t *msg, size_t mlen,
                                  uint8_t *ct,
                                  uint8_t tag[ZAFE_TAG_LEN])
{
    forkskinny_zafe_hash(ks, ad, adlen, msg, mlen, tag);
    forkskinny_zafe_encrypt(ks, tag, msg, mlen, ct);
}

int forkskinny_zafe_decrypt_verify(const zafe_key_t *ks,
                                   const uint8_t *ad, size_t adlen,
                                   const uint8_t *ct, size_t clen,
                                   const uint8_t tag[ZAFE_TAG_LEN],
                                   uint8_t *msg)
{
    forkskinny_zafe_decrypt(ks, tag, ct, clen, msg);

    if (forkskinny_zafe_verify(ks, ad, adlen, msg, clen, tag) != 0) {
        ct_memzero(msg, clen);
        return -1;
    }

    return 0;
}