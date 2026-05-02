#ifndef FORKSKINNY_ZAFE_OPT_H
#define FORKSKINNY_ZAFE_OPT_H

#include "forkskinny_zafe.h"

int forkskinny_zafe_opt_auth(const zafe_key_t *ks,
                             const uint8_t *ad, size_t adlen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t tag[ZAFE_TAG_LEN]);

int forkskinny_zafe_opt_verify(const zafe_key_t *ks,
                               const uint8_t *ad, size_t adlen,
                               const uint8_t *msg, size_t mlen,
                               const uint8_t tag[ZAFE_TAG_LEN]);

void forkskinny_zafe_opt_encrypt(const zafe_key_t *ks,
                                 const uint8_t tag[ZAFE_TAG_LEN],
                                 const uint8_t *msg, size_t mlen,
                                 uint8_t *ct);

void forkskinny_zafe_opt_decrypt(const zafe_key_t *ks,
                                 const uint8_t tag[ZAFE_TAG_LEN],
                                 const uint8_t *ct, size_t clen,
                                 uint8_t *msg);

int forkskinny_zafe_opt_encrypt_auth(const zafe_key_t *ks,
                                     const uint8_t *ad, size_t adlen,
                                     const uint8_t *msg, size_t mlen,
                                     uint8_t *ct,
                                     uint8_t tag[ZAFE_TAG_LEN]);

int forkskinny_zafe_opt_decrypt_verify(const zafe_key_t *ks,
                                       const uint8_t *ad, size_t adlen,
                                       const uint8_t *ct, size_t clen,
                                       const uint8_t tag[ZAFE_TAG_LEN],
                                       uint8_t *msg);

#endif
