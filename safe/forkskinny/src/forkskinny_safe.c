#include "forkskinny_safe.h"
#include "internal-forkskinny.h"
#include "gctr-3.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#define N       16
#define TWO_N   32
#define KEY_LEN 16
#define SAFE_IV_LEN 32

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

// gf multiplication
static void xor32(uint8_t dst[32], const uint8_t src[32])
{
    for (int i = 0; i < 32; i++) {
        dst[i] ^= src[i];
    }
}

static void shl1_32(uint8_t x[32])
{
    for (int i = 0; i < 31; i++) {
        x[i] = (uint8_t)((x[i] << 1) | (x[i + 1] >> 7));
    }
    x[31] <<= 1;
}

static void gf_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint8_t z[32] = {0};
    uint8_t v[32];

    memcpy(v, a, 32);

    for (int byte = 0; byte < 32; byte++) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((b[byte] >> bit) & 1U) {
                xor32(z, v);
            }

            {
                uint8_t msb = v[0] & 0x80U;
                shl1_32(v);

                if (msb) {
                    /* XOR low terms: x^10 + x^5 + x^2 + 1 */
                    v[30] ^= 0x04; /* x^10 */
                    v[31] ^= 0x25; /* x^5 + x^2 + 1 */
                }
            }
        }
    }

    memcpy(out, z, 32);
}

// pad10
static size_t pad10(uint8_t *out, const uint8_t *in, size_t len)
{
    size_t padded_len = len + 1 + ((TWO_N - ((len + 1) % TWO_N)) % TWO_N);

    if (len > 0) {
        memcpy(out, in, len);
    }

    out[len] = 0x80;
    if (padded_len > len + 1) {
        memset(out + len + 1, 0, padded_len - len - 1);
    }

    return padded_len;
}

// SFMac
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

int sfmac(const uint8_t key[KEY_LEN],
          const uint8_t *ad, size_t ad_len,
          const uint8_t *msg, size_t msg_len,
          uint8_t *tag, size_t tag_len)
{
    uint8_t T[TWO_N];
    uint8_t L[TWO_N];
    uint8_t tk[TWO_N];
    uint8_t zero[N] = {0};
    uint8_t tmp[TWO_N];
    uint8_t U[N];

    uint8_t *X;
    size_t a_pad_len, m_pad_len, x_len;
    size_t off = 0;

    if (!key || !tag) {
        return -1;
    }
    if ((ad_len && !ad) || (msg_len && !msg)) {
        return -1;
    }
    if (tag_len > TWO_N) {
        return -1;
    }

    /* lengths after Pad10 */
    a_pad_len = ad_len + 1 + ((TWO_N - ((ad_len + 1) % TWO_N)) % TWO_N);
    m_pad_len = msg_len + 1 + ((TWO_N - ((msg_len + 1) % TWO_N)) % TWO_N);

    /* X = Pad10(A) || Pad10(M) || |A|_n || |M|_n */
    x_len = a_pad_len + m_pad_len + TWO_N;
    X = (uint8_t *)malloc(x_len);
    if (!X) {
        return -1;
    }

    off += pad10(X + off, ad, ad_len);
    off += pad10(X + off, msg, msg_len);

    encode_bitlen_be128(X + off, ad_len);
    off += N;

    encode_bitlen_be128(X + off, msg_len);
    off += N;

    /* T <- 0^(2n) */
    memset(T, 0, TWO_N);

    /* L <- [ F_K^(0^(t+1))(0^n) ]_(2n) */
    memset(tk, 0, TWO_N);         /* tweak = 0...0 */
    memcpy(tk + N, key, KEY_LEN); /* tk = tweak || key */
    forkskinny_128_256_encrypt(tk, L, L + N, zero);

    /* for each 32-byte block: T <- (T XOR X[i]) gf_mul L */
    for (size_t i = 0; i < x_len; i += TWO_N) {
        for (size_t j = 0; j < TWO_N; ++j) {
            tmp[j] = (uint8_t)(T[j] ^ X[i + j]);
        }
        gf_mul(T, tmp, L);
    }

    /* U || V <- [T]_(n+t) */
    memcpy(U, T, N);
    memcpy(tk, T + N, N);

    /* force tweak to (0 || V) */
    tk[0] &= 0x7FU;
    memcpy(tk + N, key, KEY_LEN);

    /* T <- F_K^(0 || V)(U) */
    forkskinny_128_256_encrypt(tk, T, T + N, U);

    /* return first tag_len bytes */
    memcpy(tag, T, tag_len);

    free(X);
    return 0;
}

static void safe_iv_from_tag(const uint8_t tag[SAFE_TAG_LEN],
                             uint8_t iv[SAFE_IV_LEN])
{
    memcpy(iv, tag, SAFE_IV_LEN);
}

/* ------------------------------------------------------------------------- */
/* public API                                                                */
/* ------------------------------------------------------------------------- */

void forkskinny_safe_keygen(const uint8_t key[SAFE_KEY_LEN], safe_key_t *ks)
{
    memcpy(ks->key, key, SAFE_KEY_LEN);
}

int forkskinny_safe_auth(const safe_key_t *ks,
                         const uint8_t *ad, size_t adlen,
                         const uint8_t *msg, size_t mlen,
                         uint8_t tag[SAFE_TAG_LEN])
{
    return sfmac(ks->key, ad, adlen, msg, mlen, tag, SAFE_TAG_LEN);
}

int forkskinny_safe_verify(const safe_key_t *ks,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *msg, size_t mlen,
                           const uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t computed[SAFE_TAG_LEN];
    int rc;

    rc = sfmac(ks->key, ad, adlen, msg, mlen, computed, SAFE_TAG_LEN);
    if (rc != 0) {
        ct_memzero(computed, sizeof(computed));
        return -1;
    }

    rc = ct_memcmp_eq(computed, tag, SAFE_TAG_LEN) ? 0 : -1;
    ct_memzero(computed, sizeof(computed));
    return rc;
}

void forkskinny_safe_encrypt(const safe_key_t *ks,
                             const uint8_t tag[SAFE_TAG_LEN],
                             const uint8_t *pt, size_t ptlen,
                             uint8_t *ct)
{
    uint8_t iv[SAFE_IV_LEN];

    safe_iv_from_tag(tag, iv);
    gctr_crypt(ks->key, iv, pt, ptlen, ct);
    ct_memzero(iv, sizeof(iv));
}

void forkskinny_safe_decrypt(const safe_key_t *ks,
                             const uint8_t tag[SAFE_TAG_LEN],
                             const uint8_t *ct, size_t ctlen,
                             uint8_t *pt)
{
    uint8_t iv[SAFE_IV_LEN];

    safe_iv_from_tag(tag, iv);
    gctr_crypt(ks->key, iv, ct, ctlen, pt);
    ct_memzero(iv, sizeof(iv));
}

int forkskinny_safe_encrypt_auth(const safe_key_t *ks,
                                 const uint8_t *ad, size_t adlen,
                                 const uint8_t *msg, size_t mlen,
                                 uint8_t *ct,
                                 uint8_t tag[SAFE_TAG_LEN])
{
    uint8_t iv[SAFE_IV_LEN];
    int rc;

    rc = sfmac(ks->key, ad, adlen, msg, mlen, tag, SAFE_TAG_LEN);
    if (rc != 0) {
        return -1;
    }

    safe_iv_from_tag(tag, iv);
    gctr_crypt(ks->key, iv, msg, mlen, ct);
    ct_memzero(iv, sizeof(iv));

    return 0;
}

int forkskinny_safe_decrypt_verify(const safe_key_t *ks,
                                   const uint8_t *ad, size_t adlen,
                                   const uint8_t *ct, size_t clen,
                                   const uint8_t tag[SAFE_TAG_LEN],
                                   uint8_t *msg)
{
    uint8_t iv[SAFE_IV_LEN];
    uint8_t computed[SAFE_TAG_LEN];
    int rc;

    safe_iv_from_tag(tag, iv);
    gctr_crypt(ks->key, iv, ct, clen, msg);
    ct_memzero(iv, sizeof(iv));

    rc = sfmac(ks->key, ad, adlen, msg, clen, computed, SAFE_TAG_LEN);
    if (rc != 0) {
        ct_memzero(computed, sizeof(computed));
        ct_memzero(msg, clen);
        return -1;
    }

    rc = ct_memcmp_eq(computed, tag, SAFE_TAG_LEN) ? 0 : -1;
    ct_memzero(computed, sizeof(computed));

    if (rc != 0) {
        ct_memzero(msg, clen);
        return -1;
    }

    return 0;
}