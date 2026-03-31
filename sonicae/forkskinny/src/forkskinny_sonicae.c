#include "forkskinny_sonicae.h"
#include "forkskinny_supersonic.h"
#include "gctr-3-prime.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* keygen removed: callers should initialize `sonicae_key_t` directly (memcpy) */

void forkskinny_sonicae_auth(const sonicae_key_t *ks,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *pt, size_t ptlen,
                             uint8_t tag[SS_TAG_BYTES])
{
    /* current build only uses AD = empty */
    (void)ad;
    (void)adlen;

    forkskinny_supersonic_tag(ks->key, pt, ptlen, tag);
}

void forkskinny_sonicae_encrypt(const sonicae_key_t *ks,
                                const uint8_t tag[SS_TAG_BYTES],
                                const uint8_t *pt, size_t ptlen,
                                uint8_t *ct)
{
    gctr_3_prime(ks->key, tag, pt, ptlen, ct);
}

void forkskinny_sonicae_decrypt(const sonicae_key_t *ks,
                                const uint8_t tag[SS_TAG_BYTES],
                                const uint8_t *ct, size_t ctlen,
                                uint8_t *pt)
{
    gctr_3_prime(ks->key, tag, ct, ctlen, pt);
}

int forkskinny_sonicae_verify(const sonicae_key_t *ks,
                              const uint8_t *ad, size_t adlen,
                              const uint8_t *pt, size_t ptlen,
                              const uint8_t tag[SS_TAG_BYTES])
{
    uint8_t tag_r[SS_TAG_BYTES];
    uint8_t diff = 0u;

    forkskinny_sonicae_auth(ks, ad, adlen, pt, ptlen, tag_r);

    for (size_t i = 0; i < SS_TAG_BYTES; ++i) {
        diff |= (uint8_t)(tag_r[i] ^ tag[i]);
    }

    return (diff == 0u) ? 0 : -1;
}

void forkskinny_sonicae_encrypt_auth(const sonicae_key_t *ks,
                                     const uint8_t *ad, size_t adlen,
                                     const uint8_t *pt, size_t ptlen,
                                     uint8_t *ct,
                                     uint8_t tag[SS_TAG_BYTES])
{
    forkskinny_sonicae_auth(ks, ad, adlen, pt, ptlen, tag);
    forkskinny_sonicae_encrypt(ks, tag, pt, ptlen, ct);
}

int forkskinny_sonicae_decrypt_verify(const sonicae_key_t *ks,
                                      const uint8_t *ad, size_t adlen,
                                      const uint8_t *ct, size_t ctlen,
                                      const uint8_t tag[SS_TAG_BYTES],
                                      uint8_t *pt)
{
    forkskinny_sonicae_decrypt(ks, tag, ct, ctlen, pt);

    if (forkskinny_sonicae_verify(ks, ad, adlen, pt, ctlen, tag) != 0) {
        memset(pt, 0, ctlen);
        return -1;
    }

    return 0;
}