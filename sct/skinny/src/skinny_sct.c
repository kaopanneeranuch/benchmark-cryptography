#include "skinny_sct.h"
#include "internal-skinny128.h"
#include <stdint.h>
#include <string.h>

#define SCT_BLOCK_LEN 16
#define SCT_IV_LEN 15

static void sct_build_tk(uint8_t tk[32], const uint8_t key[16], const uint8_t tweak[16])
{
    memcpy(tk, tweak, 16);
    memcpy(tk + 16, key, 16);
}

void skinny_encrypt(const uint8_t *key,
                    const uint8_t tweak[16],
                    const uint8_t in[16],
                    uint8_t out[16])
{
    uint8_t tk[32];
    sct_build_tk(tk, key, tweak);
    skinny_128_256_encrypt_tk_full(tk, out, in);
}

static void sct_set_counter_tweak(uint8_t tweak[16], uint8_t prefix, uint64_t ctr)
{
    memset(tweak, 0, 16);
    tweak[0] = prefix;

    // put the 64-bit counter in the low bytes of tweak[1..15]
    for (int i = 15; i >= 8; --i)
    {
        tweak[i] = (uint8_t)ctr;
        ctr >>= 8;
    }
}

static void sct_inc_iv(uint8_t iv[SCT_IV_LEN])
{
    for (int i = SCT_IV_LEN - 1; i >= 0; --i)
    {
        iv[i]++;
        if (iv[i] != 0)
            break;
    }
}

/*
 * CTRT:
 *   C_i = M_i xor E_K^{(1, IV)}(N)
 *   IV  = Inc(IV)
 *
 * Same function for encrypt and decrypt.
 */
void skinny_sct_ctrt(const sct_key_t *ks,
                     const uint8_t nonce[SCT_NONCE_LEN],
                     const uint8_t iv_in[SCT_IV_LEN],
                     const uint8_t *in, size_t len,
                     uint8_t *out)
{
    uint8_t tweak[16];
    uint8_t stream[16];
    uint8_t iv[SCT_IV_LEN];
    size_t off, take;

    memcpy(iv, iv_in, SCT_IV_LEN);

    for (off = 0; off < len; off += SCT_BLOCK_LEN)
    {
        take = len - off;
        if (take > SCT_BLOCK_LEN)
            take = SCT_BLOCK_LEN;

        tweak[0] = 1;
        memcpy(tweak + 1, iv, SCT_IV_LEN);

        skinny_encrypt(ks->key, tweak, nonce, stream);

        for (size_t j = 0; j < take; j++)
            out[off + j] = in[off + j] ^ stream[j];

        sct_inc_iv(iv);
    }
}

/* keygen removed -- callers should initialize the key structure directly, e.g.
 * memcpy(ks.key, bench_key, SCT_KEY_LEN);
 */

/*
 * EPWC:
 *   auth := E^(2,0)(N) xor E^(2,1)(N)
 *   xor in AD blocks with prefixes 2/3
 *   xor in M  blocks with prefixes 4/5
 *   tag := E^(4,0)(auth)
 */
void skinny_sct_hash(const sct_key_t *ks,
                     const uint8_t nonce[SCT_NONCE_LEN],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *msg, size_t mlen,
                     uint8_t tag[SCT_TAG_LEN])
{
    uint8_t tweak[16];
    uint8_t auth[16];
    uint8_t tmp[16];
    uint8_t block[16];
    size_t off, take;

    /* auth = E^(2,0)(N) xor E^(2,1)(N) */
    sct_set_counter_tweak(tweak, 2, 0);
    skinny_encrypt(ks->key, tweak, nonce, auth);

    sct_set_counter_tweak(tweak, 2, 1);
    skinny_encrypt(ks->key, tweak, nonce, tmp);

    for (int i = 0; i < 16; i++)
        auth[i] ^= tmp[i];

    off = 0;
    while (off + SCT_BLOCK_LEN < adlen)
    {
        sct_set_counter_tweak(tweak, 2, (uint64_t)(off / SCT_BLOCK_LEN) + 2);
        skinny_encrypt(ks->key, tweak, ad + off, tmp);

        for (int i = 0; i < 16; i++)
            auth[i] ^= tmp[i];

        off += SCT_BLOCK_LEN;
    }

    if (adlen > 0)
    {
        take = adlen - off;

        if (take == SCT_BLOCK_LEN)
        {
            sct_set_counter_tweak(tweak, 2, (uint64_t)(off / SCT_BLOCK_LEN) + 2);
            skinny_encrypt(ks->key, tweak, ad + off, tmp);
        }
        else
        {
            memset(block, 0, 16);
            memcpy(block, ad + off, take);
            block[take] = 0x80;

            sct_set_counter_tweak(tweak, 3, (uint64_t)(off / SCT_BLOCK_LEN) + 2);
            skinny_encrypt(ks->key, tweak, block, tmp);
        }

        for (int i = 0; i < 16; i++)
            auth[i] ^= tmp[i];
    }

    /* Message: complete blocks use prefix 4, final partial uses prefix 5.
       Counters are 1,2,3,... */
    off = 0;
    while (off + SCT_BLOCK_LEN < mlen)
    {
        sct_set_counter_tweak(tweak, 4, (uint64_t)(off / SCT_BLOCK_LEN) + 1);
        skinny_encrypt(ks->key, tweak, msg + off, tmp);

        for (int i = 0; i < 16; i++)
            auth[i] ^= tmp[i];

        off += SCT_BLOCK_LEN;
    }

    if (mlen > 0)
    {
        take = mlen - off;

        if (take == SCT_BLOCK_LEN)
        {
            sct_set_counter_tweak(tweak, 4, (uint64_t)(off / SCT_BLOCK_LEN) + 1);
            skinny_encrypt(ks->key, tweak, msg + off, tmp);
        }
        else
        {
            memset(block, 0, 16);
            memcpy(block, msg + off, take);
            block[take] = 0x80;

            sct_set_counter_tweak(tweak, 5, (uint64_t)(off / SCT_BLOCK_LEN) + 1);
            skinny_encrypt(ks->key, tweak, block, tmp);
        }

        for (int i = 0; i < 16; i++)
            auth[i] ^= tmp[i];
    }

    /* tag = E^(4,0)(auth) */
    sct_set_counter_tweak(tweak, 4, 0);
    skinny_encrypt(ks->key, tweak, auth, tag);
}

int skinny_sct_verify(const sct_key_t *ks,
                      const uint8_t nonce[SCT_NONCE_LEN],
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *msg, size_t mlen,
                      const uint8_t tag[SCT_TAG_LEN])
{
    uint8_t computed[SCT_TAG_LEN];
    unsigned diff = 0;

    skinny_sct_hash(ks, nonce, ad, adlen, msg, mlen, computed);

    for (int i = 0; i < SCT_TAG_LEN; i++)
        diff |= (unsigned)(computed[i] ^ tag[i]);

    return diff ? -1 : 0;
}

void skinny_sct_encrypt_auth(const sct_key_t *ks,
                             const uint8_t nonce[SCT_NONCE_LEN],
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t *ct,
                             uint8_t tag[SCT_TAG_LEN])
{
    uint8_t iv[SCT_IV_LEN];

    skinny_sct_hash(ks, nonce, ad, adlen, msg, mlen, tag);

    /* Conv(tag): truncate 16-byte tag to 15-byte IV */
    memcpy(iv, tag, SCT_IV_LEN);

    skinny_sct_ctrt(ks, nonce, iv, msg, mlen, ct);
}

int skinny_sct_decrypt_verify(const sct_key_t *ks,
                              const uint8_t nonce[SCT_NONCE_LEN],
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *ct, size_t clen,
                              const uint8_t tag[SCT_TAG_LEN],
                              uint8_t *msg)
{
    uint8_t iv[SCT_IV_LEN];
    uint8_t computed[SCT_TAG_LEN];
    unsigned diff = 0;

    memcpy(iv, tag, SCT_IV_LEN);
    skinny_sct_ctrt(ks, nonce, iv, ct, clen, msg);

    skinny_sct_hash(ks, nonce, ad, adlen, msg, clen, computed);

    for (int i = 0; i < SCT_TAG_LEN; i++)
        diff |= (unsigned)(computed[i] ^ tag[i]);

    if (diff)
    {
        memset(msg, 0, clen);
        return -1;
    }

    return 0;
}