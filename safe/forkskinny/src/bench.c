#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include <string.h>
#include <stdint.h>
#include "forkskinny_safe.h"
#include "bench.h"

/* ── configuration ──────────────────────────────────────── */
#define WARMUP_ITERS   10
#define BENCH_ITERS   100
#define MESSAGE_LEN   100
#define AD_LEN         0    /* set >0 to benchmark with AD */

/* work buffers */
static uint8_t pt_buf[MESSAGE_LEN];
static uint8_t ct_buf[MESSAGE_LEN];
static uint8_t dec_buf[MESSAGE_LEN];
static uint8_t tag_buf[SAFE_TAG_LEN];
#if AD_LEN > 0
static uint8_t ad_buf[AD_LEN];
#else
static uint8_t *ad_buf = NULL;
#endif
static safe_key_t ks;

static const uint8_t bench_key[SAFE_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
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
    printk("--- ForkSkinny SAFE Correctness (msg=%d ad=%d) ---\n",
           MESSAGE_LEN, AD_LEN);

    fill_pattern(pt_buf, MESSAGE_LEN);
#if AD_LEN > 0
    fill_pattern(ad_buf, AD_LEN);
#endif
    forkskinny_safe_keygen(bench_key, &ks);

    /* encrypt + auth */
    forkskinny_safe_encrypt(&ks,
                            ad_buf, AD_LEN,
                            pt_buf, MESSAGE_LEN,
                            ct_buf, tag_buf);

    print_hex("PT[0..15]: ", pt_buf, 16);
    print_hex("CT[0..15]: ", ct_buf, 16);
    print_hex("TAG:       ", tag_buf, SAFE_TAG_LEN);

    /* decrypt + verify */
    int rc = forkskinny_safe_decrypt(&ks,
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
        forkskinny_safe_keygen(bench_key, &ks);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        forkskinny_safe_keygen(bench_key, &ks);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);
    }
    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "keygen",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

// static void bench_hash(void)
// {
//     timing_t start, end;
//     uint64_t total_c = 0, total_ns = 0;

//     fill_pattern(pt_buf, MESSAGE_LEN);
//     forkskinny_safe_keygen(bench_key, &ks);

//     for (int i = 0; i < WARMUP_ITERS; i++)
//         forkskinny_safe_auth(&ks,
//                      ad_buf, AD_LEN,
//                      pt_buf, MESSAGE_LEN, tag_buf);

//     for (int i = 0; i < BENCH_ITERS; i++) {
//         start = timing_counter_get();
//         forkskinny_safe_auth(&ks,
//                      ad_buf, AD_LEN,
//                      pt_buf, MESSAGE_LEN, tag_buf);
//         end = timing_counter_get();
//         uint64_t c = timing_cycles_get(&start, &end);
//         total_c  += c;
//         total_ns += timing_cycles_to_ns(c);
//     }
//     printk("  %-14s: %10llu cycles  |  %10llu ns\n", "hash (tag)",
//            (unsigned long long)(total_c / BENCH_ITERS),
//            (unsigned long long)(total_ns / BENCH_ITERS));
// }
static void bench_hash(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    forkskinny_safe_keygen(bench_key, &ks);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        forkskinny_safe_reset_counters();
        forkskinny_safe_auth(&ks,
                     ad_buf, AD_LEN,
                     pt_buf, MESSAGE_LEN, tag_buf);
    }

    uint64_t total_gf = 0;
    uint64_t total_tprf = 0;
    uint64_t total_blocks = 0;

    for (int i = 0; i < BENCH_ITERS; i++) {
        forkskinny_safe_reset_counters();

        start = timing_counter_get();
        forkskinny_safe_auth(&ks,
                     ad_buf, AD_LEN,
                     pt_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();

        uint64_t c = timing_cycles_get(&start, &end);
        total_c  += c;
        total_ns += timing_cycles_to_ns(c);

        total_gf     += forkskinny_safe_get_gf256_mul_count();
        total_tprf   += forkskinny_safe_get_tprf_eval_count();
        total_blocks += forkskinny_safe_get_absorbed_block_count();
    }

    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "hash (tag)",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));

    printk("    SAFE counters: gf256_mul=%llu, tprf_eval=%llu, absorb_blocks=%llu\n",
           (unsigned long long)(total_gf / BENCH_ITERS),
           (unsigned long long)(total_tprf / BENCH_ITERS),
           (unsigned long long)(total_blocks / BENCH_ITERS));
}

static void bench_encrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    forkskinny_safe_keygen(bench_key, &ks);

    /* Precompute tag once so we measure FEnc only */
    forkskinny_safe_auth(&ks, ad_buf, AD_LEN, pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        forkskinny_safe_fenc_encrypt(&ks,
                                     tag_buf,
                                     pt_buf, MESSAGE_LEN,
                                     ct_buf);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        forkskinny_safe_fenc_encrypt(&ks,
                                     tag_buf,
                                     pt_buf, MESSAGE_LEN,
                                     ct_buf);
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
    fill_pattern(ad_buf, AD_LEN);
    forkskinny_safe_keygen(bench_key, &ks);

    /* Precompute tag and ciphertext once so we measure FEnc only */
    forkskinny_safe_auth(&ks, ad_buf, AD_LEN, pt_buf, MESSAGE_LEN, tag_buf);
    forkskinny_safe_fenc_encrypt(&ks,
                                 tag_buf,
                                 pt_buf, MESSAGE_LEN,
                                 ct_buf);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        forkskinny_safe_fenc_decrypt(&ks,
                                     tag_buf,
                                     ct_buf, MESSAGE_LEN,
                                     dec_buf);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        forkskinny_safe_fenc_decrypt(&ks,
                                     tag_buf,
                                     ct_buf, MESSAGE_LEN,
                                     dec_buf);
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
    forkskinny_safe_keygen(bench_key, &ks);
    forkskinny_safe_auth(&ks,
                         ad_buf, AD_LEN,
                         pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++)
        forkskinny_safe_verify(&ks,
                       ad_buf, AD_LEN,
                       pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        forkskinny_safe_verify(&ks,
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
void bench_safe_all(void)
{
    printk("[FORKSKINNY SAFE] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  %-14s  %10s  %12s\n", "operation", "cycles", "ns");

    bench_keygen();
    bench_hash();
    bench_encrypt();
    bench_decrypt();
    bench_verify();

    printk("--- Benchmark complete ---\n\n");
}