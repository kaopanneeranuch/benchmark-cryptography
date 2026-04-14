#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include <string.h>
#include <stdint.h>
#include <psa/crypto.h>
#include "aesgcm.h"
#include "bench.h"
#include "ghash.h"
#include "gf.h"

/* ── configuration ──────────────────────────────────────── */
#define WARMUP_ITERS   10
#define BENCH_ITERS   100
#define MESSAGE_LEN   100
#define AD_LEN         0

/* work buffers */
static uint8_t pt_buf[MESSAGE_LEN];
static uint8_t ct_buf[MESSAGE_LEN];
static uint8_t dec_buf[MESSAGE_LEN];
#if 1
static uint8_t tag_buf[16];
#else
static uint8_t tag_buf[OCB_TAG_LEN];
#endif
#if AD_LEN > 0
static uint8_t ad_buf[AD_LEN];
#else
static uint8_t *ad_buf = NULL;
#endif
/* no ocb key structure for GCM; use raw key */
static const uint8_t bench_key[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t bench_nonce[12] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab
};

static void fill_pattern(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(i & 0xff);
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("%s", label);
    for (size_t i = 0; i < len; i++) printk("%02x", buf[i]);
    printk("\n");
}

/* ── correctness check ─────────────────────────────────── */
void verify_correctness(void)
{
    printk("--- AES-256 GCM Correctness (msg=%d ad=%d) ---\n",
           MESSAGE_LEN, AD_LEN);

    fill_pattern(pt_buf, MESSAGE_LEN);
#if AD_LEN > 0
    fill_pattern(ad_buf, AD_LEN);
#endif

    /* produce ciphertext + tag using GCM API (combined) */
    aes_256_gcm_encrypt_auth(bench_key, bench_nonce, 12,
                       ad_buf, AD_LEN,
                       pt_buf, MESSAGE_LEN,
                       ct_buf, tag_buf);

    print_hex("PT[0..15]: ", pt_buf, 16);
    print_hex("CT[0..15]: ", ct_buf, 16);
    print_hex("TAG:       ", tag_buf, 16);

    int rc = aes_256_gcm_decrypt_verify(bench_key, bench_nonce, 12,
                                ad_buf, AD_LEN,
                                ct_buf, MESSAGE_LEN,
                                tag_buf, dec_buf);

    print_hex("DEC[0..15]:", dec_buf, 16);
    printk("Decrypt+Verify: %s\n", rc == 0 ? "OK" : "FAIL");

    if (memcmp(pt_buf, dec_buf, MESSAGE_LEN) == 0)
        printk("Plaintext match: OK\n");
    else
        printk("Plaintext match: FAIL\n");

    printk("--- End correctness ---\n\n");
}

/* ── individual benchmarks ─────────────────────────────── */

/* keygen benchmark removed */

static void bench_hash(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
#if AD_LEN > 0
    fill_pattern(ad_buf, AD_LEN);
#endif

    /* probe: one un-timed call to count primitive invocations */
    aes_counters_reset();
    aes_256_gcm_auth(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    uint32_t enc_per_op = g_aes_enc_calls;

    /* measure auth (tag-only) */
    for (int i = 0; i < WARMUP_ITERS; i++)
        aes_256_gcm_auth(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        aes_256_gcm_auth(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "hash (tag)",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_encrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* probe: one un-timed call to count primitive invocations */
    aes_counters_reset();
    aes_256_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    uint32_t enc_per_op = g_aes_enc_calls;

    /* CTR-mode encryption (no tag) */
    for (int i = 0; i < WARMUP_ITERS; i++)
        aes_256_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        aes_256_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "encrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_decrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* produce ciphertext */
    aes_256_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);

    /* probe: one un-timed call to count primitive invocations */
    aes_counters_reset();
    aes_256_gcm_decrypt(bench_key, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
    uint32_t enc_per_op = g_aes_enc_calls;

    for (int i = 0; i < WARMUP_ITERS; i++)
        aes_256_gcm_decrypt(bench_key, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        aes_256_gcm_decrypt(bench_key, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "decrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_verify(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* produce valid ciphertext + tag first (combined API) */
    aes_256_gcm_encrypt_auth(bench_key, bench_nonce, 12,
                       ad_buf, AD_LEN,
                       pt_buf, MESSAGE_LEN,
                       ct_buf, tag_buf);

    /* probe: one un-timed call to count primitive invocations */
    aes_counters_reset();
    (void)aes_256_gcm_verify(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    uint32_t enc_per_op = g_aes_enc_calls;

    for (int i = 0; i < WARMUP_ITERS; i++)
        (void)aes_256_gcm_verify(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        (void)aes_256_gcm_verify(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "verify",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

/* ── PSA Crypto library benchmarks ─────────────────────────── */

static psa_key_id_t s_lib_key;

static bool lib_key_init(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_status_t st = psa_import_key(&attr, bench_key, 32, &s_lib_key);
    if (st != PSA_SUCCESS) {
        printk("  lib: psa_import_key failed (%d)\n", (int)st);
        return false;
    }
    return true;
}

/* one-shot: psa_aead_encrypt (CTR encrypt + GHASH + tag) */
static void bench_lib_combined(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;
    static uint8_t output[MESSAGE_LEN + 16];
    size_t output_len;

    fill_pattern(pt_buf, MESSAGE_LEN);

    for (int i = 0; i < WARMUP_ITERS; i++)
        psa_aead_encrypt(s_lib_key, PSA_ALG_GCM, bench_nonce, 12,
                          ad_buf, AD_LEN, pt_buf, MESSAGE_LEN,
                          output, sizeof(output), &output_len);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        psa_aead_encrypt(s_lib_key, PSA_ALG_GCM, bench_nonce, 12,
                          ad_buf, AD_LEN, pt_buf, MESSAGE_LEN,
                          output, sizeof(output), &output_len);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "lib combined",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

/* one-shot decrypt to pair with encrypt */
static void bench_lib_decrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;
    static uint8_t enc_output[MESSAGE_LEN + 16];
    static uint8_t dec_output[MESSAGE_LEN];
    size_t out_len;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* produce valid ciphertext+tag first */
    size_t enc_len;
    psa_aead_encrypt(s_lib_key, PSA_ALG_GCM, bench_nonce, 12,
                      ad_buf, AD_LEN, pt_buf, MESSAGE_LEN,
                      enc_output, sizeof(enc_output), &enc_len);

    for (int i = 0; i < WARMUP_ITERS; i++)
        psa_aead_decrypt(s_lib_key, PSA_ALG_GCM, bench_nonce, 12,
                          ad_buf, AD_LEN, enc_output, enc_len,
                          dec_output, sizeof(dec_output), &out_len);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        psa_aead_decrypt(s_lib_key, PSA_ALG_GCM, bench_nonce, 12,
                          ad_buf, AD_LEN, enc_output, enc_len,
                          dec_output, sizeof(dec_output), &out_len);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "lib decrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

/* ── top-level entry ───────────────────────────────────── */
void bench_gcm_all(void)
{
    printk("[AES-256 GCM] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  sizes:  key=%d  nonce=%d  tag=%d  pt=%d  ct=%d  ad=%d  (bytes)\n",
           (int)sizeof(bench_key), (int)sizeof(bench_nonce), 16,
           MESSAGE_LEN, MESSAGE_LEN, AD_LEN);
    printk("  %-14s  %10s  %12s\n", "operation", "cycles", "ns");

    printk("\n[Our implementation]\n");
    bench_hash();
    bench_encrypt();
    bench_decrypt();
    bench_verify();

    printk("\n[PSA Crypto library (AES-256-GCM)]\n");
    if (lib_key_init()) {
        bench_lib_combined();
        bench_lib_decrypt();
        psa_destroy_key(s_lib_key);
    }

    printk("\n--- Benchmark complete ---\n\n");
}