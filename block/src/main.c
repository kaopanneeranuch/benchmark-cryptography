#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <mbedtls/aes.h>
#include "rijndael256.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "butterknife.h"
#include "internal-skinny128.h"
#include "internal-forkskinny.h"

/* Deoxys-I-128 custom implementation (deoxysi/) */
void deoxys_I_aead_encrypt_128(const uint8_t *message, size_t m_len,
                               const uint8_t *key, const uint8_t *nonce,
                               uint8_t *ciphertext, size_t *c_len);
int deoxys_I_aead_decrypt_128(uint8_t *message, size_t *m_len,
                              const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ciphertext, size_t c_len);

/* Deoxys-I-128 reference implementation (deoxysi128/deoxysi128/ref, renamed) */
void deoxys128_ref_aead_encrypt(const uint8_t *ass_data, size_t ass_data_len,
                                const uint8_t *message, size_t m_len,
                                const uint8_t *key, const uint8_t *nonce,
                                uint8_t *ciphertext, size_t *c_len);
int deoxys128_ref_aead_decrypt(const uint8_t *ass_data, size_t ass_data_len,
                               uint8_t *message, size_t *m_len,
                               const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *ciphertext, size_t c_len);
void aesTweakEncrypt_deoxysi128_ref(uint32_t tweakey_size,
                                    const uint8_t pt[16],
                                    const uint8_t key[],
                                    uint8_t ct[16]);

/* Deoxys-I-256 reference implementation (deoxysi256/deoxysi256/ref) */
void deoxys_aead_encrypt(const uint8_t *ass_data, size_t ass_data_len,
                         const uint8_t *message, size_t m_len,
                         const uint8_t *key, const uint8_t *nonce,
                         uint8_t *ciphertext, size_t *c_len);
int deoxys_aead_decrypt(const uint8_t *ass_data, size_t ass_data_len,
                        uint8_t *message, size_t *m_len,
                        const uint8_t *key, const uint8_t *nonce,
                        const uint8_t *ciphertext, size_t c_len);
void aesTweakEncrypt(uint32_t tweakey_size,
                     const uint8_t pt[16],
                     const uint8_t key[],
                     uint8_t ct[16]);

#define WARMUP_ITERS  10
#define BENCH_ITERS   100

static volatile uint8_t sink;

static const uint8_t key_16[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t key_32[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t key_48[48] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};
static const uint8_t plaintext[16] = {
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
};
static const uint8_t plaintext_32[32] = {
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34,
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
};
static const uint8_t nonce_8[8] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
};

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printk("  %-30s : ", label);
    for (size_t i = 0; i < len; i++) printk("%02x", data[i]);
    printk("\n");
}

/* ------------------------------------------------------------------ */
/* Helper: run one benchmark, print result                             */
/* ------------------------------------------------------------------ */
#define BENCH_BEGIN(name_)                                  \
    do {                                                    \
        const char *_name = (name_);                        \
        timing_t _start, _end;                              \
        uint64_t _total_c = 0, _total_ns = 0;

#define BENCH_WARMUP(call_)                                 \
        for (int _i = 0; _i < WARMUP_ITERS; _i++) { call_; }

#define BENCH_MEASURE(call_)                                \
        for (int _i = 0; _i < BENCH_ITERS; _i++) {         \
            _start = timing_counter_get();                  \
            call_;                                          \
            _end = timing_counter_get();                    \
            uint64_t _c = timing_cycles_get(&_start, &_end);\
            _total_c  += _c;                                \
            _total_ns += timing_cycles_to_ns(_c);           \
        }

#define BENCH_END()                                         \
        printk("  %-30s : %10" PRIu64 " cycles | %10" PRIu64 " ns\n", \
               _name,                                       \
               _total_c  / BENCH_ITERS,                     \
               _total_ns / BENCH_ITERS);                    \
    } while (0)

/* ------------------------------------------------------------------ */

static void bench_skinny128_256(void)
{
    uint8_t output[16];
    skinny_128_256_key_schedule_t ks;
    skinny_128_256_init(&ks, key_32);

    BENCH_BEGIN("SKINNY-128-256")
    BENCH_WARMUP(skinny_128_256_encrypt(&ks, output, plaintext))
    BENCH_MEASURE(skinny_128_256_encrypt(&ks, output, plaintext))
    sink ^= output[0];
    BENCH_END();
}

static void bench_forkskinny128_256_1leg(void)
{
    uint8_t out_right[16];

    BENCH_BEGIN("ForkSkinny-128-256 1-leg")
    BENCH_WARMUP(forkskinny_128_256_encrypt(key_32, NULL, out_right, plaintext))
    BENCH_MEASURE(forkskinny_128_256_encrypt(key_32, NULL, out_right, plaintext))
    sink ^= out_right[0];
    BENCH_END();
}

static void bench_forkskinny128_256_2leg(void)
{
    uint8_t out_left[16], out_right[16];

    BENCH_BEGIN("ForkSkinny-128-256 2-leg")
    BENCH_WARMUP(forkskinny_128_256_encrypt(key_32, out_left, out_right, plaintext))
    BENCH_MEASURE(forkskinny_128_256_encrypt(key_32, out_left, out_right, plaintext))
    sink ^= out_left[0] ^ out_right[0];
    BENCH_END();
}

static void bench_deoxysbc128(void)
{
    uint8_t output[16];
    uint8_t tk[32];
    memcpy(tk, key_32, 32);

    BENCH_BEGIN("Deoxys-BC-128")
    BENCH_WARMUP(aesTweakEncrypt_deoxysi128_ref(256, plaintext, tk, output))
    BENCH_MEASURE(aesTweakEncrypt_deoxysi128_ref(256, plaintext, tk, output))
    sink ^= output[0];
    BENCH_END();
}

static void bench_deoxysbc256(void)
{
    uint8_t output[16];
    uint8_t tk[32];
    memcpy(tk, key_32, 32);

    BENCH_BEGIN("Deoxys-BC-256")
    BENCH_WARMUP(aesTweakEncrypt(256, (uint8_t *)plaintext, tk, output))
    BENCH_MEASURE(aesTweakEncrypt(256, (uint8_t *)plaintext, tk, output))
    sink ^= output[0];
    BENCH_END();
}

static void bench_butterknife256(uint8_t num_branches, const char *label)
{
    uint8_t output[16];
    uint32_t rtk[4 * 16];
    butterknife_256_precompute_rtk(key_32, rtk, num_branches);

    BENCH_BEGIN(label)
    BENCH_WARMUP(butterknife_256_encrypt_w_rtk(rtk, output, plaintext, num_branches))
    BENCH_MEASURE(butterknife_256_encrypt_w_rtk(rtk, output, plaintext, num_branches))
    sink ^= output[0];
    BENCH_END();
}

static void bench_aes128(void)
{
    uint8_t output[16];
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key_16, 128);

    BENCH_BEGIN("AES-128")
    BENCH_WARMUP(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, output))
    BENCH_MEASURE(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, output))
    sink ^= output[0];
    BENCH_END();

    mbedtls_aes_free(&ctx);
}

static void bench_aes256(void)
{
    uint8_t output[16];
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key_32, 256);

    BENCH_BEGIN("AES-256")
    BENCH_WARMUP(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, output))
    BENCH_MEASURE(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, output))
    sink ^= output[0];
    BENCH_END();

    mbedtls_aes_free(&ctx);
}

static void bench_rijndael256(void)
{
    uint8_t output[32];
    rijndael256_ctx_t ctx;
    rijndael256_set_key(&ctx, key_32);

    BENCH_BEGIN("Rijndael-256")
    BENCH_WARMUP(rijndael256_encrypt(&ctx, plaintext_32, output))
    BENCH_MEASURE(rijndael256_encrypt(&ctx, plaintext_32, output))
    sink ^= output[0];
    BENCH_END();
}

/* ------------------------------------------------------------------ */
/* Deoxys-I AEAD comparison                                            */
/*   deoxysi256/ref  →  Deoxys-I-256  (key=32 B, nonce=8 B)          */
/*   deoxysi         →  Deoxys-I-128  (key=16 B, nonce=8 B, SKINNY)  */
/*   deoxysi128/ref  →  Deoxys-I-128  (key=16 B, nonce=8 B, Deoxys-BC)*/
/* ------------------------------------------------------------------ */
static void verify_deoxys_aead(void)
{
    uint8_t ct256[32];   /* 16-byte CT + 16-byte tag */
    uint8_t ct128[32];
    uint8_t ct128ref[32];
    uint8_t recovered[16];
    size_t  len256 = 0, len128 = 0, len128ref = 0;
    size_t  recovered_len = 0;
    bool ok256 = false, ok128 = false, ok128ref = false;
    bool ct_match_128 = false;

    deoxys_aead_encrypt(NULL, 0, plaintext, 16,
                        key_32, nonce_8, ct256, &len256);

    deoxys_I_aead_encrypt_128(plaintext, 16,
                              key_16, nonce_8, ct128, &len128);

    deoxys128_ref_aead_encrypt(NULL, 0, plaintext, 16,
                               key_16, nonce_8, ct128ref, &len128ref);

    ok256 = (len256 == 32);
    if (ok256) {
        recovered_len = 0;
        ok256 = (deoxys_aead_decrypt(NULL, 0, recovered, &recovered_len,
                                     key_32, nonce_8, ct256, len256) == 0) &&
                (recovered_len == 16) &&
                (memcmp(recovered, plaintext, 16) == 0);
    }

    ok128 = (len128 == 32);
    if (ok128) {
        recovered_len = 0;
        ok128 = (deoxys_I_aead_decrypt_128(recovered, &recovered_len,
                                           key_16, nonce_8, ct128, len128) == 0) &&
                (recovered_len == 16) &&
                (memcmp(recovered, plaintext, 16) == 0);
    }

    ok128ref = (len128ref == 32);
    if (ok128ref) {
        recovered_len = 0;
        ok128ref = (deoxys128_ref_aead_decrypt(NULL, 0, recovered, &recovered_len,
                                               key_16, nonce_8, ct128ref, len128ref) == 0) &&
                   (recovered_len == 16) &&
                   (memcmp(recovered, plaintext, 16) == 0);
    }

    ct_match_128 = (len128 == len128ref) &&
                   (memcmp(ct128, ct128ref, len128) == 0);

    printk("\n=== Deoxys-I AEAD CT Comparison ===\n");
    print_hex("Deoxys-I-128 CT  (deoxysi128)", ct128ref,      16);
    print_hex("Deoxys-I-128 tag (deoxysi128)", ct128ref + 16, 16);
    print_hex("Deoxys-I-256 CT  (deoxysi256)", ct256,         16);
    print_hex("Deoxys-I-256 tag (deoxysi256)", ct256 + 16,    16);
    print_hex("Deoxys-I-128 CT  (deoxysi)",    ct128,         16);
    print_hex("Deoxys-I-128 tag (deoxysi)",    ct128 + 16,    16);
    printk("  %-30s : %s\n", "Decrypt check deoxysi256/ref", ok256 ? "PASS" : "FAIL");
    printk("  %-30s : %s\n", "Decrypt check deoxysi/deoxysi", ok128 ? "PASS" : "FAIL");
    printk("  %-30s : %s\n", "Decrypt check deoxysi128/ref", ok128ref ? "PASS" : "FAIL");
    printk("  %-30s : %s\n", "deoxysi vs deoxysi128/ref", ct_match_128 ? "MATCH" : "MISMATCH");
    printk("\n");
}

static void bench_deoxysI256(void)
{
    uint8_t ct[32];
    size_t  ct_len = 0;

    BENCH_BEGIN("Deoxys-I-256 (deoxysi256)")
    BENCH_WARMUP(deoxys_aead_encrypt(NULL, 0, plaintext, 16,
                                     key_32, nonce_8, ct, &ct_len))
    BENCH_MEASURE(deoxys_aead_encrypt(NULL, 0, plaintext, 16,
                                      key_32, nonce_8, ct, &ct_len))
    sink ^= ct[0];
    BENCH_END();
}

static void bench_deoxysI128(void)
{
    uint8_t ct[32];
    size_t  ct_len = 0;

    BENCH_BEGIN("Deoxys-I-128 (deoxysi)")
    BENCH_WARMUP(deoxys_I_aead_encrypt_128(plaintext, 16,
                                           key_16, nonce_8, ct, &ct_len))
    BENCH_MEASURE(deoxys_I_aead_encrypt_128(plaintext, 16,
                                            key_16, nonce_8, ct, &ct_len))
    sink ^= ct[0];
    BENCH_END();
}

static void bench_deoxysI128_ref(void)
{
    uint8_t ct[32];
    size_t  ct_len = 0;

    BENCH_BEGIN("Deoxys-I-128 (deoxysi128/ref)")
    BENCH_WARMUP(deoxys128_ref_aead_encrypt(NULL, 0, plaintext, 16,
                                            key_16, nonce_8, ct, &ct_len))
    BENCH_MEASURE(deoxys128_ref_aead_encrypt(NULL, 0, plaintext, 16,
                                             key_16, nonce_8, ct, &ct_len))
    sink ^= ct[0];
    BENCH_END();
}

int main(void)
{
    timing_init();
    timing_start();

    verify_deoxys_aead();

    printk("=== Block Primitive Benchmark ===\n");
    printk("Single block (16 bytes), key schedule pre-computed\n");
    printk("iters=%d, warmup=%d\n\n", BENCH_ITERS, WARMUP_ITERS);
    printk("  %-30s   %10s     %10s\n", "Primitive", "avg cycles", "avg ns");
    printk("  %-30s   %10s     %10s\n",
           "------------------------------", "----------", "----------");

    bench_skinny128_256();
    bench_forkskinny128_256_1leg();
    bench_forkskinny128_256_2leg();
    bench_deoxysbc128();
    bench_deoxysbc256();
    bench_deoxysI256();
    bench_deoxysI128();
    bench_deoxysI128_ref();
    bench_butterknife256(1, "Butterknife-256 1-leg");
    bench_butterknife256(7, "Butterknife-256 7-leg");
    bench_butterknife256(8, "Butterknife-256 8-leg");
    bench_aes128();
    bench_aes256();
    bench_rijndael256();
    timing_stop();

    printk("\nDone (sink=%u).\n", sink);
    return 0;
}
