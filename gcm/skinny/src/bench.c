#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include <string.h>
#include <stdint.h>
#include "skinny_gcm.h"
#include "bench.h"
#include "ghash.h"
#include "gf.h"
#include "SKINNY-AEAD/internal-skinny128.h"

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
static const uint8_t bench_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
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
    printk("--- SKINNY GCM Correctness (msg=%d ad=%d) ---\n",
           MESSAGE_LEN, AD_LEN);

    fill_pattern(pt_buf, MESSAGE_LEN);
#if AD_LEN > 0
    fill_pattern(ad_buf, AD_LEN);
#endif

    /* produce ciphertext + tag using GCM API (combined) */
    skinny_gcm_encrypt_auth(bench_key, bench_nonce, 12,
                       ad_buf, AD_LEN,
                       pt_buf, MESSAGE_LEN,
                       ct_buf, tag_buf);

    print_hex("PT[0..15]: ", pt_buf, 16);
    print_hex("CT[0..15]: ", ct_buf, 16);
    print_hex("TAG:       ", tag_buf, 16);

    int rc = skinny_gcm_decrypt_verify(bench_key, bench_nonce, 12,
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
    skinny_counters_reset();
    skinny_gcm_auth(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    uint32_t enc_per_op = g_skinny128_256_enc_calls;

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_gcm_auth(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_gcm_auth(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "hash (tag)",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [prim/op] SKINNY-128-256: enc=%lu\n", (unsigned long)enc_per_op);
}

static void bench_encrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* probe: one un-timed call to count primitive invocations */
    skinny_counters_reset();
    skinny_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    uint32_t enc_per_op = g_skinny128_256_enc_calls;

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "encrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [prim/op] SKINNY-128-256: enc=%lu\n", (unsigned long)enc_per_op);
}

static void bench_decrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* produce ciphertext */
    skinny_gcm_encrypt(bench_key, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);

    /* probe: one un-timed call to count primitive invocations */
    skinny_counters_reset();
    skinny_gcm_decrypt(bench_key, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
    uint32_t enc_per_op = g_skinny128_256_enc_calls;

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_gcm_decrypt(bench_key, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_gcm_decrypt(bench_key, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "decrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [prim/op] SKINNY-128-256: enc=%lu\n", (unsigned long)enc_per_op);
}

static void bench_verify(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    /* produce valid ciphertext + tag first (combined API) */
    skinny_gcm_encrypt_auth(bench_key, bench_nonce, 12,
                       ad_buf, AD_LEN,
                       pt_buf, MESSAGE_LEN,
                       ct_buf, tag_buf);

    /* probe: one un-timed call to count primitive invocations */
    skinny_counters_reset();
    (void)skinny_gcm_verify(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    uint32_t enc_per_op = g_skinny128_256_enc_calls;

    for (int i = 0; i < WARMUP_ITERS; i++)
        (void)skinny_gcm_verify(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        (void)skinny_gcm_verify(bench_key, bench_nonce, 12, ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "verify",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [prim/op] SKINNY-128-256: enc=%lu\n", (unsigned long)enc_per_op);
}

/* ── top-level entry ───────────────────────────────────── */
void bench_gcm_all(void)
{
    printk("[SKINNY GCM] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  sizes:  key=%d  nonce=%d  tag=%d  pt=%d  ct=%d  ad=%d  (bytes)\n",
           (int)sizeof(bench_key), (int)sizeof(bench_nonce), 16,
           MESSAGE_LEN, MESSAGE_LEN, AD_LEN);
    printk("  %-14s  %10s  %12s\n", "operation", "cycles", "ns");

    bench_hash();
    bench_encrypt();
    bench_decrypt();
    bench_verify();

    printk("--- Benchmark complete ---\n\n");
}