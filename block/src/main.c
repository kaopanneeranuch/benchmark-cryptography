#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <mbedtls/aes.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "butterknife.h"
#include "internal-skinny128.h"
#include "internal-forkskinny.h"
#include "../deoxysi256/deoxysi256/ref/tweakableBC.h"
/* Unity-include deoxysi128's tweakableBC — rename every non-static symbol
   to avoid clashes with the deoxysi256 tweakableBC.c compiled separately. */
#define choose_lfsr      choose_lfsr_deoxysi128
#define G                G_deoxysi128
#define H                H_deoxysi128
#define deoxysKeySetupEnc deoxysKeySetupEnc_deoxysi128
#define deoxysKeySetupDec deoxysKeySetupDec_deoxysi128
#define aesTweakEncrypt  aesTweakEncrypt_deoxysi128
#define aesTweakDecrypt  aesTweakDecrypt_deoxysi128
#include "../deoxysi128/deoxysi128/ref/tweakableBC.c"
#undef choose_lfsr
#undef G
#undef H
#undef deoxysKeySetupEnc
#undef deoxysKeySetupDec
#undef aesTweakEncrypt
#undef aesTweakDecrypt
#include "../deoxysi256/deoxysi256/ref/deoxys.h"   /* deoxys_aead_encrypt       (Deoxys-I-256) */
/* Forward-declare only what we call from deoxysi/deoxys.c — avoids pulling
   in forkskinny-opt32/skinny.h which conflicts with internal-skinny128.h.  */
void deoxys_I_aead_encrypt_128(const uint8_t *message, size_t m_len,
                                const uint8_t *key, const uint8_t *nonce,
                                uint8_t *ciphertext, size_t *c_len);

/* Unity-include skinny.c to provide skinny_128_256_init_tk1/tk2/encrypt_with_tks
   and skinny_64_192_* needed by deoxysi/deoxys.c.  Rename skinny_128_256_encrypt
   so it doesn't clash with internal-skinny128.c's same-named symbol.         */
#define skinny_128_256_encrypt skinny_128_256_encrypt__fks_unused
#include "../forkskinny-opt32/skinny.c"
#undef skinny_128_256_encrypt

/* Unity-include Deoxys-I-128 ref (deoxysi128) — rename exported symbols to
   avoid clash with Deoxys-I-256's deoxys_aead_encrypt from deoxysi256.      */
#define deoxys_aead_encrypt deoxys128_aead_encrypt
#define deoxys_aead_decrypt deoxys128_aead_decrypt
#include "../deoxysi128/deoxysi128/ref/deoxysi.c"
#undef deoxys_aead_encrypt
#undef deoxys_aead_decrypt

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

static void bench_deoxysbc128(void)
{
    uint8_t output[16];
    uint8_t tk[32];
    memcpy(tk, key_32, 32);

    BENCH_BEGIN("Deoxys-BC-128")
    BENCH_WARMUP(aesTweakEncrypt_deoxysi128(256, (uint8_t *)plaintext, tk, output))
    BENCH_MEASURE(aesTweakEncrypt_deoxysi128(256, (uint8_t *)plaintext, tk, output))
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
    size_t  len256 = 0, len128 = 0, len128ref = 0;

    deoxys_aead_encrypt(NULL, 0, plaintext, 16,
                        key_32, nonce_8, ct256, &len256);

    deoxys_I_aead_encrypt_128(plaintext, 16,
                              key_16, nonce_8, ct128, &len128);

    deoxys128_aead_encrypt(NULL, 0, plaintext, 16,
                           key_16, nonce_8, ct128ref, &len128ref);

    printk("\n=== Deoxys-I AEAD CT Comparison ===\n");
    print_hex("Deoxys-I-256 CT  (deoxysi256)", ct256,         16);
    print_hex("Deoxys-I-256 tag (deoxysi256)", ct256 + 16,    16);
    print_hex("Deoxys-I-128 CT  (deoxysi)",    ct128,         16);
    print_hex("Deoxys-I-128 tag (deoxysi)",    ct128 + 16,    16);
    print_hex("Deoxys-I-128 CT  (deoxysi128)", ct128ref,      16);
    print_hex("Deoxys-I-128 tag (deoxysi128)", ct128ref + 16, 16);
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

    BENCH_BEGIN("Deoxys-I-128 (deoxysi128)")
    BENCH_WARMUP(deoxys128_aead_encrypt(NULL, 0, plaintext, 16,
                                        key_16, nonce_8, ct, &ct_len))
    BENCH_MEASURE(deoxys128_aead_encrypt(NULL, 0, plaintext, 16,
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
    bench_deoxysbc256();
    bench_deoxysbc128();
    bench_deoxysI256();
    bench_deoxysI128();
    bench_deoxysI128_ref();
    bench_butterknife256(1, "Butterknife-256 1-leg");
    bench_butterknife256(7, "Butterknife-256 7-leg");
    bench_butterknife256(8, "Butterknife-256 8-leg");
    bench_aes128();
    bench_aes256();

    timing_stop();

    printk("\nDone (sink=%u).\n", sink);
    return 0;
}
