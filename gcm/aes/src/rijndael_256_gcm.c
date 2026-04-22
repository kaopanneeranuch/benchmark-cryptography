#include "rijndael_256_gcm.h"

#include <gcrypt.h>
#include <string.h>

uint32_t g_rijndael256_block_calls = 0;

void rijndael256_gcm_counters_reset(void)
{
    g_rijndael256_block_calls = 0;
}

uint32_t rijndael256_gcm_get_block_calls(void)
{
    return g_rijndael256_block_calls;
}

static void inc_be32(uint8_t ctr[32])
{
    for (int i = 31; i >= 28; --i) {
        if (++ctr[i] != 0) {
            break;
        }
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

static void xor_block(uint8_t out[32], const uint8_t in[32])
{
    for (int i = 0; i < 32; ++i) {
        out[i] ^= in[i];
    }
}

static uint64_t load64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) |
           ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) |
           ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) |
           ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8)  |
           ((uint64_t)in[7]);
}

static void store64_be(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

/* GF(2^256) multiplication for GHASH with 256-bit blocks */
static void gf_mul_256(const uint8_t X[32], const uint8_t Y[32], uint8_t out[32])
{
    /* Load values from 4 x 64-bit chunks */
    uint64_t Xvals[4], Yvals[4];
    
    for (int i = 0; i < 4; i++) {
        Xvals[i] = load64_be(X + (i * 8));
        Yvals[i] = load64_be(Y + (i * 8));
    }

    uint64_t Z[4] = {0, 0, 0, 0};

    /* GF multiplication bit-by-bit */
    for (int bit = 0; bit < 256; ++bit) {
        int chunk = bit / 64;
        int bitpos = 63 - (bit % 64);
        int bit_val = (int)((Xvals[chunk] >> bitpos) & 1U);

        if (bit_val) {
            for (int i = 0; i < 4; i++) {
                Z[i] ^= Yvals[i];
            }
        }

        /* Reduction */
        int lsb = (int)(Yvals[3] & 1U);
        uint64_t new_y3 = (Yvals[3] >> 1) | ((Yvals[2] & 1U) << 63);
        uint64_t new_y2 = (Yvals[2] >> 1) | ((Yvals[1] & 1U) << 63);
        uint64_t new_y1 = (Yvals[1] >> 1) | ((Yvals[0] & 1U) << 63);
        uint64_t new_y0 = (Yvals[0] >> 1);

        Yvals[3] = new_y3;
        Yvals[2] = new_y2;
        Yvals[1] = new_y1;
        Yvals[0] = new_y0;

        if (lsb) {
            /* Rijndael-256 irreducible polynomial */
            Yvals[0] ^= 0x4F00000000000000ULL;
        }
    }

    for (int i = 0; i < 4; i++) {
        store64_be(out + (i * 8), Z[i]);
    }
}

static void ghash_256(const uint8_t H[32],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t out[32])
{
    uint8_t Y[32] = {0};
    uint8_t block[32];
    uint8_t tmp[32];
    size_t off = 0;

    while (off + 32 <= aad_len) {
        memcpy(block, aad + off, 32);
        xor_block(Y, block);
        gf_mul_256(Y, H, tmp);
        memcpy(Y, tmp, 32);
        off += 32;
    }

    if (off < aad_len) {
        size_t rem = aad_len - off;
        memset(block, 0, sizeof(block));
        memcpy(block, aad + off, rem);
        xor_block(Y, block);
        gf_mul_256(Y, H, tmp);
        memcpy(Y, tmp, 32);
    }

    off = 0;
    while (off + 32 <= ct_len) {
        memcpy(block, ct + off, 32);
        xor_block(Y, block);
        gf_mul_256(Y, H, tmp);
        memcpy(Y, tmp, 32);
        off += 32;
    }

    if (off < ct_len) {
        size_t rem = ct_len - off;
        memset(block, 0, sizeof(block));
        memcpy(block, ct + off, rem);
        xor_block(Y, block);
        gf_mul_256(Y, H, tmp);
        memcpy(Y, tmp, 32);
    }

    /* Append length block */
    memset(block, 0, sizeof(block));
    store64_be(block + 16, (uint64_t)aad_len * 8);
    store64_be(block + 24, (uint64_t)ct_len * 8);
    xor_block(Y, block);
    gf_mul_256(Y, H, tmp);
    memcpy(Y, tmp, 32);

    memcpy(out, Y, 32);
}

static gcry_cipher_hd_t rijndael256_create_cipher(const uint8_t key[RIJNDAEL256_KEY_LEN])
{
    gcry_cipher_hd_t handle;
    gcry_error_t err;

    err = gcry_cipher_open(&handle, GCRY_CIPHER_RIJNDAEL, GCRY_CIPHER_MODE_ECB, 0);
    if (err) {
        return NULL;
    }

    err = gcry_cipher_setkey(handle, key, RIJNDAEL256_KEY_LEN);
    if (err) {
        gcry_cipher_close(handle);
        return NULL;
    }

    return handle;
}

void rijndael256_gcm_ctr_crypt(const uint8_t key[RIJNDAEL256_KEY_LEN],
                               const uint8_t iv[RIJNDAEL256_GCM_NONCE_LEN],
                               const uint8_t *in, size_t len,
                               uint8_t *out)
{
    gcry_cipher_hd_t cipher = rijndael256_create_cipher(key);
    if (!cipher) {
        return;
    }

    uint8_t ctr[32];
    uint8_t block[32];
    size_t off = 0;

    memset(ctr, 0, sizeof(ctr));
    memcpy(ctr, iv, RIJNDAEL256_GCM_NONCE_LEN);
    ctr[31] = 2;  /* Counter starts at 2 for Rijndael-256 */

    while (off < len) {
        gcry_cipher_encrypt(cipher, block, sizeof(block), ctr, sizeof(ctr));
        g_rijndael256_block_calls++;

        size_t block_len = (len - off) > 32 ? 32 : (len - off);
        for (size_t i = 0; i < block_len; ++i) {
            out[off + i] = in[off + i] ^ block[i];
        }

        off += block_len;
        inc_be32(ctr);
    }

    gcry_cipher_close(cipher);
}

void rijndael256_gcm_auth(const uint8_t key[RIJNDAEL256_KEY_LEN],
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct, size_t ct_len,
                          uint8_t tag[RIJNDAEL256_GCM_TAG_LEN])
{
    gcry_cipher_hd_t cipher = rijndael256_create_cipher(key);
    if (!cipher) {
        return;
    }

    /* Generate H = E(K, 0) */
    uint8_t H[32];
    uint8_t zero[32] = {0};
    gcry_cipher_encrypt(cipher, H, sizeof(H), zero, sizeof(zero));
    g_rijndael256_block_calls++;

    /* GHASH */
    uint8_t ghash_out[32];
    ghash_256(H, aad, aad_len, ct, ct_len, ghash_out);

    /* Generate counter for tag encryption */
    uint8_t ctr[32];
    memset(ctr, 0, sizeof(ctr));
    memcpy(ctr, iv, iv_len);
    ctr[31] = 1;

    /* Encrypt GHASH output */
    uint8_t tag_block[32];
    gcry_cipher_encrypt(cipher, tag_block, sizeof(tag_block), ctr, sizeof(ctr));
    g_rijndael256_block_calls++;

    /* XOR and truncate to tag length */
    for (size_t i = 0; i < RIJNDAEL256_GCM_TAG_LEN; ++i) {
        tag[i] = ghash_out[i] ^ tag_block[i];
    }

    gcry_cipher_close(cipher);
}

int rijndael256_gcm_verify(const uint8_t key[RIJNDAEL256_KEY_LEN],
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[RIJNDAEL256_GCM_TAG_LEN])
{
    uint8_t computed_tag[RIJNDAEL256_GCM_TAG_LEN];
    
    rijndael256_gcm_auth(key, iv, iv_len, aad, aad_len, ct, ct_len, computed_tag);
    
    return ct_memcmp_eq(tag, computed_tag, RIJNDAEL256_GCM_TAG_LEN);
}

void rijndael256_gcm_encrypt_auth(const uint8_t key[RIJNDAEL256_KEY_LEN],
                                  const uint8_t *iv, size_t iv_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint8_t *ct,
                                  uint8_t tag[RIJNDAEL256_GCM_TAG_LEN])
{
    rijndael256_gcm_ctr_crypt(key, iv, pt, pt_len, ct);
    rijndael256_gcm_auth(key, iv, iv_len, aad, aad_len, ct, pt_len, tag);
}

int rijndael256_gcm_decrypt_verify(const uint8_t key[RIJNDAEL256_KEY_LEN],
                                   const uint8_t *iv, size_t iv_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ct, size_t ct_len,
                                   const uint8_t tag[RIJNDAEL256_GCM_TAG_LEN],
                                   uint8_t *pt)
{
    if (!rijndael256_gcm_verify(key, iv, iv_len, aad, aad_len, ct, ct_len, tag)) {
        return 0;
    }

    rijndael256_gcm_ctr_crypt(key, iv, ct, ct_len, pt);
    return 1;
}
