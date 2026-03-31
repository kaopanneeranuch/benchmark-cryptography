#include "forkskinny_zafe.h"
#include "internal-forkskinny.h"
#include "fenc.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define N            16
#define TWO_N        32
#define KEY_LEN      16

#define ZT_BYTES     15
#define ZBLOCK_LEN   (N + ZT_BYTES)

/* ----------------------------- small helpers ----------------------------- */

static void ct_memzero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}

static int ct_memcmp_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        dst[i] ^= src[i];
    }
}

static size_t pad10_len(size_t len, size_t block_len)
{
    return len + 1 + ((block_len - ((len + 1) % block_len)) % block_len);
}

static size_t pad10(uint8_t *out, const uint8_t *in, size_t len, size_t block_len)
{
    size_t padded_len = pad10_len(len, block_len);

    if (len > 0 && in != NULL) {
        memcpy(out, in, len);
    }

    out[len] = 0x80;
    if (padded_len > len + 1) {
        memset(out + len + 1, 0, padded_len - len - 1);
    }

    return padded_len;
}

static void encode_bitlen_be128(uint8_t out[N], size_t len_bytes)
{
    uint64_t hi = ((uint64_t)len_bytes) >> 61;
    uint64_t lo = ((uint64_t)len_bytes) << 3;

    memset(out, 0, N);

    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(hi & 0xFFU);
        hi >>= 8;
    }
    for (int i = 15; i >= 8; --i) {
        out[i] = (uint8_t)(lo & 0xFFU);
        lo >>= 8;
    }
}

/* doubling in GF(2^128), polynomial x^128 + x^7 + x^2 + x + 1 */
static void gf_mul_x_n(uint8_t x[N])
{
    uint8_t carry = (uint8_t)(x[0] >> 7);

    for (int i = 0; i < N - 1; ++i) {
        x[i] = (uint8_t)((x[i] << 1) | (x[i + 1] >> 7));
    }
    x[N - 1] <<= 1;

    if (carry) {
        x[N - 1] ^= 0x87U;
    }
}

/* ----------------------------- ForkSkinny helper ----------------------------- */

static void ztbc_encrypt(const uint8_t key[KEY_LEN],
                         uint8_t domain,
                         const uint8_t tweak_t[ZT_BYTES],
                         const uint8_t in[N],
                         uint8_t out[N])
{
    uint8_t tk[TWO_N];

    memset(tk, 0, sizeof(tk));
    tk[0] = domain;                    /* domain byte */
    memcpy(tk + 1, tweak_t, ZT_BYTES); /* remaining 120 tweak bits */
    memcpy(tk + N, key, KEY_LEN);      /* 16-byte key */

    /*
     * ZHASH/ZFIN use a single n-bit TBC output per call.  Request only the
     * needed ForkSkinny branch so the implementation matches the paper's
     * single-leg E_K^i(T, M) abstraction instead of computing and discarding
     * the second branch.
     */
    forkskinny_128_256_encrypt(tk, out, NULL, in);
}

/* ----------------------------- ZHASH / ZMAC / ZFMac ----------------------------- */

static int zhash(const uint8_t key[KEY_LEN],
                 const uint8_t *x, size_t xlen,
                 uint8_t U[N],
                 uint8_t V[ZT_BYTES])
{
    uint8_t Ll[N], Lr[N];
    uint8_t zero_n[N] = {0};
    uint8_t zero_t[ZT_BYTES] = {0};
    uint8_t one_t[ZT_BYTES] = {0};

    if ((xlen % ZBLOCK_LEN) != 0) {
        return -1;
    }

    memset(U, 0, N);
    memset(V, 0, ZT_BYTES);

    /* Ll <- E^9_K(0^t, 0^n) */
    ztbc_encrypt(key, 9, zero_t, zero_n, Ll);

    /* Lr <- E^9_K(0^(t-1)1, 0^n) */
    one_t[ZT_BYTES - 1] = 0x01U;
    ztbc_encrypt(key, 9, one_t, zero_n, Lr);

    for (size_t off = 0; off < xlen; off += ZBLOCK_LEN) {
        const uint8_t *Xl = x + off;
        const uint8_t *Xr = x + off + N;

        uint8_t Sl[N];
        uint8_t Sr[ZT_BYTES];
        uint8_t Cl[N];
        uint8_t Cr[ZT_BYTES];

        /* Sl <- Ll XOR Xl */
        for (size_t i = 0; i < N; ++i) {
            Sl[i] = (uint8_t)(Ll[i] ^ Xl[i]);
        }

        /* Sr <- msb_t(Lr) XOR Xr */
        for (size_t i = 0; i < ZT_BYTES; ++i) {
            Sr[i] = (uint8_t)(Lr[i] ^ Xr[i]);
        }

        /* Cl <- E^8_K(Sr, Sl) */
        ztbc_encrypt(key, 8, Sr, Sl, Cl);

        /* Cr <- msb_t(Cl) XOR Xr */
        for (size_t i = 0; i < ZT_BYTES; ++i) {
            Cr[i] = (uint8_t)(Cl[i] ^ Xr[i]);
        }

        /* U <- 2(U XOR Cl) */
        xor_into(U, Cl, N);
        gf_mul_x_n(U);

        /* V <- V XOR Cr */
        xor_into(V, Cr, ZT_BYTES);

        /* (Ll, Lr) <- (2Ll, 2Lr) */
        gf_mul_x_n(Ll);
        gf_mul_x_n(Lr);
    }

    return 0;
}

static void zfin(const uint8_t key[KEY_LEN],
                 uint8_t i,
                 const uint8_t U[N],
                 const uint8_t V[ZT_BYTES],
                 uint8_t out[TWO_N])
{
    uint8_t a[N], b[N], c[N], d[N];

    ztbc_encrypt(key, (uint8_t)(i + 0), V, U, a);
    ztbc_encrypt(key, (uint8_t)(i + 1), V, U, b);
    ztbc_encrypt(key, (uint8_t)(i + 2), V, U, c);
    ztbc_encrypt(key, (uint8_t)(i + 3), V, U, d);

    for (size_t j = 0; j < N; ++j) {
        out[j]     = (uint8_t)(a[j] ^ b[j]);
        out[N + j] = (uint8_t)(c[j] ^ d[j]);
    }
}

static int zmac(const uint8_t key[KEY_LEN],
                const uint8_t *msg, size_t msg_len,
                uint8_t out[TWO_N])
{
    uint8_t U[N];
    uint8_t V[ZT_BYTES];
    uint8_t *X;
    size_t x_len;
    int rc;

    if (!key || !out) {
        return -1;
    }
    if (msg_len != 0 && !msg) {
        return -1;
    }

    /* X <- Pad10(M), with ZHASH block length n+t' = 31 bytes */
    x_len = pad10_len(msg_len, ZBLOCK_LEN);
    X = (uint8_t *)malloc(x_len);
    if (!X) {
        return -1;
    }

    (void)pad10(X, msg, msg_len, ZBLOCK_LEN);

    rc = zhash(key, X, x_len, U, V);
    free(X);
    if (rc != 0) {
        return -1;
    }

    /* if (n+t') divides |M| use i=0, else i=4 */
    if ((msg_len % ZBLOCK_LEN) == 0) {
        zfin(key, 0, U, V, out);
    } else {
        zfin(key, 4, U, V, out);
    }

    ct_memzero(U, sizeof(U));
    ct_memzero(V, sizeof(V));
    return 0;
}

static int zfmac(const uint8_t key[KEY_LEN],
                 const uint8_t *ad, size_t ad_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t *tag, size_t tag_len)
{
    uint8_t full[TWO_N];
    uint8_t *X;
    size_t a_pad_len, m_pad_len, x_len;
    size_t off = 0;
    int rc;

    if (!key || !tag) {
        return -1;
    }
    if ((ad_len != 0 && !ad) || (msg_len != 0 && !msg)) {
        return -1;
    }
    if (tag_len > TWO_N) {
        return -1;
    }

    /* X <- Pad10(A) || Pad10(M) || <|A|>_n || <|M|>_n */
    a_pad_len = pad10_len(ad_len, ZBLOCK_LEN);
    m_pad_len = pad10_len(msg_len, ZBLOCK_LEN);
    x_len = a_pad_len + m_pad_len + TWO_N;

    X = (uint8_t *)malloc(x_len);
    if (!X) {
        return -1;
    }

    off += pad10(X + off, ad, ad_len, ZBLOCK_LEN);
    off += pad10(X + off, msg, msg_len, ZBLOCK_LEN);
    encode_bitlen_be128(X + off, ad_len);
    off += N;
    encode_bitlen_be128(X + off, msg_len);
    off += N;

    rc = zmac(key, X, x_len, full);
    free(X);
    if (rc != 0) {
        ct_memzero(full, sizeof(full));
        return -1;
    }

    memcpy(tag, full, tag_len);
    ct_memzero(full, sizeof(full));
    return 0;
}

/* ----------------------------- IV derivation for GCTR core ----------------------------- */

/* fenc() expects a preformatted 32-byte IV = U || V_rep.
 * In this adaptation, ZAFE exposes a 32-byte tag and uses it directly as IV.
 */
static void zafe_iv_from_tag(const uint8_t tag[ZAFE_TAG_LEN],
                             uint8_t iv[TWO_N])
{
    memcpy(iv, tag, TWO_N);
}

/* ----------------------------- public API ----------------------------- */

int forkskinny_zafe_auth(const zafe_key_t *ks,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *msg, size_t mlen,
                         uint8_t tag[ZAFE_TAG_LEN])
{
    return zfmac(ks->mac_key, ad, adlen, msg, mlen, tag, ZAFE_TAG_LEN);
}

int forkskinny_zafe_verify(const zafe_key_t *ks,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[ZAFE_TAG_LEN])
{
    uint8_t computed[ZAFE_TAG_LEN];
    int rc;

    rc = zfmac(ks->mac_key, ad, adlen, msg, mlen, computed, ZAFE_TAG_LEN);
    if (rc != 0) {
        ct_memzero(computed, sizeof(computed));
        return -1;
    }

    rc = ct_memcmp_eq(computed, tag, ZAFE_TAG_LEN) ? 0 : -1;
    ct_memzero(computed, sizeof(computed));
    return rc;
}

void forkskinny_zafe_encrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct)
{
    uint8_t iv[TWO_N];

    zafe_iv_from_tag(tag, iv);
    fenc(ks->enc_key, iv, msg, mlen, ct);
    ct_memzero(iv, sizeof(iv));
}

void forkskinny_zafe_decrypt(const zafe_key_t *ks,
                             const uint8_t tag[ZAFE_TAG_LEN],
                             const uint8_t *ct, size_t clen,
                             uint8_t *msg)
{
    uint8_t iv[TWO_N];

    zafe_iv_from_tag(tag, iv);
    fenc(ks->enc_key, iv, ct, clen, msg);
    ct_memzero(iv, sizeof(iv));
}

int forkskinny_zafe_encrypt_auth(const zafe_key_t *ks,
                                 const uint8_t *ad, size_t adlen,
                                 const uint8_t *msg, size_t mlen,
                                 uint8_t *ct,
                                 uint8_t tag[ZAFE_TAG_LEN])
{
    int rc;

    rc = forkskinny_zafe_auth(ks, ad, adlen, msg, mlen, tag);
    if (rc != 0) {
        return -1;
    }

    forkskinny_zafe_encrypt(ks, tag, msg, mlen, ct);
    return 0;
}

int forkskinny_zafe_decrypt_verify(const zafe_key_t *ks,
                                   const uint8_t *ad, size_t adlen,
                                   const uint8_t *ct, size_t clen,
                                   const uint8_t tag[ZAFE_TAG_LEN],
                                   uint8_t *msg)
{
    int rc;

    forkskinny_zafe_decrypt(ks, tag, ct, clen, msg);

    rc = forkskinny_zafe_verify(ks, ad, adlen, msg, clen, tag);
    if (rc != 0) {
        ct_memzero(msg, clen);
        return -1;
    }

    return 0;
}