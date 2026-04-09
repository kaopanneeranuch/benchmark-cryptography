#include "ghash.h"
#include "gf.h"
#include "utils.h"
#include <string.h>

/* GHASH(H, A, C) -> out
   Processes AAD (A) and ciphertext (C) and returns 16-byte tag accumulator S.
   Uses gf_mul(X, H, product) where product = X * H in GF(2^128).
*/
void ghash(const uint8_t H[16], const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len, uint8_t out[16])
{
        uint8_t Y[16] = {0};
        uint8_t block[16];

        // proccess 16-byte blocks of aad
        size_t off = 0;
        while (off + 16 <= aad_len) {
                memcpy(block, aad + off, 16);
                xor_block(Y, block);
                uint8_t tmp[16];
                gf_mul(Y, H, tmp); 
                memcpy(Y, tmp, 16);
                off += 16;
        }
        // last part of aad block (zero-padded)
        if (off < aad_len) {
                size_t rem = aad_len - off;
                memset(block, 0, 16);
                memcpy(block, aad + off, rem);
                xor_block(Y, block);
                uint8_t tmp[16];
                gf_mul(Y, H, tmp);
                memcpy(Y, tmp, 16);
        }

        // process cipher blocks
        off = 0;
        while (off + 16 <= ct_len){
                memcpy(block, ct + off, 16);
                xor_block(Y, block);
                uint8_t tmp[16];
                gf_mul(Y, H, tmp);
                memcpy(Y, tmp, 16);
                off += 16;
        }
        if (off < ct_len) {
                size_t rem = ct_len - off;
                memset(block, 0, 16);
                memcpy(block, ct + off, rem);
                xor_block(Y, block);
                uint8_t tmp[16];
                gf_mul(Y, H, tmp);
                memcpy(Y, tmp, 16);
        }

        //64 bit of aad and 64 bit of ct
        uint64_t aad_bits = (uint64_t)aad_len * 8;
        uint64_t ct_bits = (uint64_t)ct_len * 8;
        uint8_t lenblk[16];
        store_64(lenblk, aad_bits);
        store_64(lenblk + 8, ct_bits);
        xor_block(Y, lenblk);
        uint8_t tmp[16];
        gf_mul(Y, H, tmp);
        memcpy(Y, tmp, 16);

        memcpy(out, Y, 16);
}