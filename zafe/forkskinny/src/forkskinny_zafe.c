#include "forkskinny_zafe.h"
#include "internal-forkskinny.h"
#include "fenc.h"
#include "stm32wrapper.h"

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

// static void xor_into(uint8_t *dst, const uint8_t *src, size_t len)
// {
//     for (size_t i = 0; i < len; ++i) {
//         dst[i] ^= src[i];
//     }
// }

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

// /* doubling in GF(2^128), polynomial x^128 + x^7 + x^2 + x + 1 */
// static void gf_mul_x_n(uint8_t x[N])
// {
//     uint8_t carry = (uint8_t)(x[0] >> 7);

//     for (int i = 0; i < N - 1; ++i) {
//         x[i] = (uint8_t)((x[i] << 1) | (x[i + 1] >> 7));
//     }
//     x[N - 1] <<= 1;

//     if (carry) {
//         x[N - 1] ^= 0x87U;
//     }
// }

/* ----------------------------- ZHASH / ZMAC / ZFMac (streaming, USART-based) ----------------------------- */

/* Map pasted-code macros to local definitions */
#ifndef KS
#define KS KEY_LEN
#endif
#ifndef TS
#define TS (ZT_BYTES + 1)
#endif
#ifndef BS
#define BS N
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

typedef struct {
    unsigned char tweakey[KS + TS];
    unsigned char message[BS];
    unsigned char mask_l[BS];
    unsigned char mask_r[BS];
    unsigned char out[BS * 2];
} ZmacStruct;

typedef struct {
    unsigned char u[BS];
    unsigned char v[TS];
} MacChains;

static void skinny_encrypt(unsigned char *output, unsigned char *input, unsigned char *key){
#if BS == 16
    forkskinny_128_256_encrypt(key, output, NULL, input);
#else
    /* fallback if 64-bit variant required */
    /* call appropriate ForkSkinny 64/192 primitive if available */
#endif
}

static void arrXOR(unsigned char *out, unsigned char *right, uint16_t len){
    for(uint16_t i = 0; i < len; ++i){
        out[i] ^= right[i];
    }
}

static void arrLeftByOne(unsigned char *out, int len){
    for (int i = 0;  i < len - 1;  ++i){
        out[i] = (unsigned char)((out[i] << 1) | ((out[i+1] >> 7) & 1));
    }
    out[len-1] = (unsigned char)(out[len-1] << 1);
}

static void arrMULT(unsigned char *out, uint8_t prpol, uint8_t len){
    uint8_t tmp = (out[len-1] >> 7) & 1;
    arrLeftByOne(out, len);
    out[0] ^= prpol * tmp;
}

static void ZHASH(ZmacStruct *pZmac, MacChains *pChains, unsigned char prpol){
    unsigned char tmp[TS-1], cmask[BS];
    memcpy(tmp, pZmac->tweakey + KS, TS-1);

    arrXOR(pZmac->message, pZmac->mask_l, BS);
    arrXOR(pZmac->tweakey + KS, pZmac->mask_r, MIN(TS-1, BS));

    pZmac->tweakey[KS + TS-1] = 0x08;
    skinny_encrypt(cmask, pZmac->message, pZmac->tweakey);

    arrXOR(pChains->u, cmask, BS);
    arrMULT(pChains->u, prpol, BS);

    arrXOR(tmp, cmask, MIN(TS-1, BS));
    arrXOR(pChains->v, tmp, TS-1);

    arrMULT(pZmac->mask_l, prpol, BS);
    arrMULT(pZmac->mask_r, prpol, BS);
}

static void ZFIN(ZmacStruct *pZmac, uint8_t fin){
    unsigned char tmp[BS];
    /* Y_1 */
    pZmac->tweakey[KS+TS-1] = fin;
    skinny_encrypt(pZmac->out, pZmac->message, pZmac->tweakey);

    ++pZmac->tweakey[KS+TS-1];
    skinny_encrypt(tmp, pZmac->message, pZmac->tweakey);
    arrXOR(pZmac->out, tmp, BS);

    /* Y_2 */
    ++pZmac->tweakey[KS+TS-1];
    skinny_encrypt(&pZmac->out[BS], pZmac->message, pZmac->tweakey);

    ++pZmac->tweakey[KS+TS-1];
    skinny_encrypt(tmp, pZmac->message, pZmac->tweakey);
    arrXOR(&pZmac->out[BS], tmp, BS);
}

static void ZMAC_padding(ZmacStruct *pZmac, uint8_t *fin, uint8_t res, uint64_t *cc){
    if (res){
        memset(pZmac->message, 0, BS);
        memset(pZmac->tweakey + KS, 0, TS);
        if(res >= BS){
            res -= BS;
            pZmac->tweakey[KS+res] ^= (1<<7);
            recv_USART_bytes(pZmac->message, BS,cc);
            recv_USART_bytes(pZmac->tweakey + KS, res,cc);
        } else{
            recv_USART_bytes(pZmac->message, res,cc);
            pZmac->message[res] ^= (1<<7);
        }
        *fin = 4;
    } else{
        recv_USART_bytes(pZmac->message, BS, cc);
        recv_USART_bytes(pZmac->tweakey + KS, TS-1, cc);
        *fin = 0;
    }
}

static void ZMAC_encrypt(unsigned char *out_left, unsigned char *out_right, unsigned char *key, uint32_t mlen, uint64_t *cc){
    DWT_CYCCNT = 0;
    uint8_t pbsize = TS+BS-1;
    uint8_t res = mlen%pbsize, fin = 0;
    uint16_t nP_complete = (res) ? (uint16_t)(mlen/pbsize) : (uint16_t)((mlen/pbsize)-1);
    ZmacStruct Zmac;
    MacChains Chains;

    memcpy(Zmac.tweakey, key, KS);
    memset(Zmac.tweakey + KS, 0, TS);
    memset(Zmac.message, 0, BS);
    memset(Chains.u, 0, BS);
    memset(Chains.v, 0, TS);

#if BS == 16
        unsigned char prpol = 0b10000111;
#else
        unsigned char prpol = 0b00011011;
#endif

    Zmac.tweakey[KS+TS-1] = 0x09;
    skinny_encrypt(Zmac.mask_l, Zmac.message, Zmac.tweakey);

    Zmac.tweakey[KS+TS-2] = 0x01;
    skinny_encrypt(Zmac.mask_r, Zmac.message, Zmac.tweakey);

    send_USART_bytes(&pbsize,1,cc);
    for(uint16_t i = 0;i<nP_complete; ++i){
        recv_USART_bytes(Zmac.message, BS,cc);
        recv_USART_bytes(Zmac.tweakey + KS, TS-1,cc);
        ZHASH(&Zmac, &Chains, prpol);
        send_USART_bytes(0,1,cc);
    }
    ZMAC_padding(&Zmac, &fin, res, cc);

    ZHASH(&Zmac, &Chains, prpol);
    memcpy(Zmac.tweakey + KS, Chains.v, TS);
    memcpy(Zmac.message, Chains.u, BS);
    ZFIN(&Zmac, fin);
    send_USART_bytes(0,1,cc);

    memcpy(out_left, Zmac.out, BS);
    memcpy(out_right, Zmac.out +BS, BS);
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

/* ----------------------------- zfmac wrapper (streaming) ----------------------------- */

static int zfmac(const unsigned char key[KEY_LEN],
                 const unsigned char *ad, size_t adlen,
                 const unsigned char *msg, size_t mlen,
                 unsigned char *tag, size_t taglen)
{
    unsigned char out_l[BS], out_r[BS];
    uint64_t cc = 0;

    if (taglen < TWO_N) return -1;

    ZMAC_encrypt(out_l, out_r, (unsigned char *)key, (uint32_t)mlen, &cc);

    memcpy(tag, out_l, BS);
    memcpy(tag + BS, out_r, BS);

    return 0;
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