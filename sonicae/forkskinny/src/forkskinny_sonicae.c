#include "forkskinny_sonicae.h"
#include "internal-forkskinny.h"
#include "gctr-3.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>



//public API

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