#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include <string.h>
#include <stdint.h>
#include "skinny_sct.h"
#include "bench.h"

/* ── configuration ──────────────────────────────────────── */
#define WARMUP_ITERS   10
#define BENCH_ITERS   100
#define MESSAGE_LEN   100
#define AD_LEN         0

/* work buffers */
static uint8_t pt_buf[MESSAGE_LEN];
static uint8_t ct_buf[MESSAGE_LEN];
static uint8_t dec_buf[MESSAGE_LEN];
static uint8_t tag_buf[SCT_TAG_LEN];
#if AD_LEN > 0
static uint8_t ad_buf[AD_LEN];
#else
static uint8_t *ad_buf = NULL;
#endif
static sct_key_t ks;

static const uint8_t bench_key[SCT_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t bench_nonce[SCT_NONCE_LEN] = {
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
    printk("--- SKINNY SCT Correctness (msg=%d ad=%d) ---\n",
           MESSAGE_LEN, AD_LEN);

    fill_pattern(pt_buf, MESSAGE_LEN);
#if AD_LEN > 0
    fill_pattern(ad_buf, AD_LEN);
#endif
    skinny_sct_keygen(bench_key, &ks);

    skinny_sct_encrypt_auth(&ks, bench_nonce,
                            ad_buf, AD_LEN,
                            pt_buf, MESSAGE_LEN,
                            ct_buf, tag_buf);

    print_hex("PT[0..15]: ", pt_buf, 16);
    print_hex("CT[0..15]: ", ct_buf, 16);
    print_hex("TAG:       ", tag_buf, SCT_TAG_LEN);

    int rc = skinny_sct_decrypt_verify(&ks, bench_nonce,
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

static void bench_keygen(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_sct_keygen(bench_key, &ks);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_sct_keygen(bench_key, &ks);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "keygen",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_hash(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    skinny_sct_keygen(bench_key, &ks);

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_sct_hash(&ks, bench_nonce,
                        ad_buf, AD_LEN,
                        pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_sct_hash(&ks, bench_nonce,
                        ad_buf, AD_LEN,
                        pt_buf, MESSAGE_LEN, tag_buf);
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
    skinny_sct_keygen(bench_key, &ks);
    skinny_sct_hash(&ks, bench_nonce,
                    ad_buf, AD_LEN,
                    pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_sct_encrypt(&ks, tag_buf, pt_buf, MESSAGE_LEN, ct_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_sct_encrypt(&ks, tag_buf, pt_buf, MESSAGE_LEN, ct_buf);
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
    skinny_sct_keygen(bench_key, &ks);
    skinny_sct_encrypt_auth(&ks, bench_nonce,
                            ad_buf, AD_LEN,
                            pt_buf, MESSAGE_LEN,
                            ct_buf, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_sct_decrypt(&ks, tag_buf, ct_buf, MESSAGE_LEN, dec_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_sct_decrypt(&ks, tag_buf, ct_buf, MESSAGE_LEN, dec_buf);
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
    skinny_sct_keygen(bench_key, &ks);
    skinny_sct_hash(&ks, bench_nonce,
                    ad_buf, AD_LEN,
                    pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++)
        skinny_sct_verify(&ks, bench_nonce,
                          ad_buf, AD_LEN,
                          pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        skinny_sct_verify(&ks, bench_nonce,
                          ad_buf, AD_LEN,
                          pt_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "verify",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

/* ── top-level entry ───────────────────────────────────── */
void bench_sct_all(void)
{
    printk("[SKINNY SCT] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  %-14s  %10s  %12s\n", "operation", "cycles", "ns");

    bench_keygen();
    bench_hash();
    bench_encrypt();
    bench_decrypt();
    bench_verify();

    printk("--- Benchmark complete ---\n\n");
}