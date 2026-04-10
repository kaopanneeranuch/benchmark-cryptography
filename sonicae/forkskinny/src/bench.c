#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <string.h>
#include <stdint.h>

#include "forkskinny_sonicae.h"
#include "bench.h"

/* ── configuration ──────────────────────────────────────── */
#define WARMUP_ITERS   10
#define BENCH_ITERS   100
#define MESSAGE_LEN   100

/* work buffers */
static uint8_t pt_buf[MESSAGE_LEN];
static uint8_t ct_buf[MESSAGE_LEN];
static uint8_t dec_buf[MESSAGE_LEN];
static uint8_t tag_buf[SS_TAG_BYTES];
static sonicae_key_t ks;

/* volatile sinks to stop optimization from removing work */
static volatile uint8_t bench_sink8;
static volatile uint32_t bench_sink32;

static const uint8_t bench_key[SONICAE_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static void fill_pattern(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xffu);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("%s", label);
    for (size_t i = 0; i < len; ++i) {
        printk("%02x", buf[i]);
    }
    printk("\n");
}

/* ── correctness check ─────────────────────────────────── */
void verify_correctness(void)
{
    printk("--- ForkSkinny SonicAE Correctness Check (msg = %d bytes) ---\n",
           MESSAGE_LEN);

    fill_pattern(pt_buf, MESSAGE_LEN);
    memset(ct_buf, 0, sizeof(ct_buf));
    memset(dec_buf, 0, sizeof(dec_buf));
    memset(tag_buf, 0, sizeof(tag_buf));

    memcpy(ks.key, bench_key, SONICAE_KEY_LEN);

    forkskinny_sonicae_encrypt_auth(&ks,
                                    NULL, 0,
                                    pt_buf, MESSAGE_LEN,
                                    ct_buf, tag_buf);

    print_hex("PT[0..15]:  ", pt_buf, 16);
    print_hex("CT[0..15]:  ", ct_buf, 16);
    print_hex("TAG:        ", tag_buf, SS_TAG_BYTES);

    {
        int rc = forkskinny_sonicae_decrypt_verify(&ks,
                                                   NULL, 0,
                                                   ct_buf, MESSAGE_LEN,
                                                   tag_buf, dec_buf);

        print_hex("DEC[0..15]: ", dec_buf, 16);
        printk("Decrypt+Verify: %s\n", (rc == 0) ? "OK" : "FAIL");
    }

    if (memcmp(pt_buf, dec_buf, MESSAGE_LEN) == 0) {
        printk("Plaintext match: OK\n");
    } else {
        printk("Plaintext match: FAIL\n");
    }

    printk("--- End correctness ---\n\n");
}

/* ── individual benchmarks ─────────────────────────────── */

static void bench_auth(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    memcpy(ks.key, bench_key, SONICAE_KEY_LEN);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        forkskinny_sonicae_auth(&ks, NULL, 0,
                                pt_buf, MESSAGE_LEN, tag_buf);
        bench_sink8 ^= tag_buf[0];
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        forkskinny_sonicae_auth(&ks, NULL, 0,
                                pt_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();

        bench_sink8 ^= tag_buf[0];

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c += c;
            total_ns += timing_cycles_to_ns(c);
        }
    }

    printk("  %-14s: %10llu cycles | %10llu ns\n",
           "auth (tag)",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_encrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    memcpy(ks.key, bench_key, SONICAE_KEY_LEN);

    /* precompute tag outside timing */
    forkskinny_sonicae_auth(&ks, NULL, 0, pt_buf, MESSAGE_LEN, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        forkskinny_sonicae_encrypt(&ks, tag_buf, pt_buf, MESSAGE_LEN, ct_buf);
        bench_sink8 ^= ct_buf[0];
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        forkskinny_sonicae_encrypt(&ks, tag_buf, pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();

        bench_sink8 ^= ct_buf[0];

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c += c;
            total_ns += timing_cycles_to_ns(c);
        }
    }

    printk("  %-14s: %10llu cycles | %10llu ns\n",
           "encrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_decrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    memcpy(ks.key, bench_key, SONICAE_KEY_LEN);
    forkskinny_sonicae_encrypt_auth(&ks, NULL, 0,
                                    pt_buf, MESSAGE_LEN, ct_buf, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        forkskinny_sonicae_decrypt(&ks, tag_buf, ct_buf, MESSAGE_LEN, dec_buf);
        bench_sink8 ^= dec_buf[0];
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        forkskinny_sonicae_decrypt(&ks, tag_buf, ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();

        bench_sink8 ^= dec_buf[0];

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c += c;
            total_ns += timing_cycles_to_ns(c);
        }
    }

    printk("  %-14s: %10llu cycles | %10llu ns\n",
           "decrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

static void bench_auth_check(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    int rc = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    memcpy(ks.key, bench_key, SONICAE_KEY_LEN);
    forkskinny_sonicae_encrypt_auth(&ks, NULL, 0,
                                    pt_buf, MESSAGE_LEN, ct_buf, tag_buf);
    forkskinny_sonicae_decrypt(&ks, tag_buf, ct_buf, MESSAGE_LEN, dec_buf);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        rc ^= forkskinny_sonicae_verify(&ks, NULL, 0,
                                        dec_buf, MESSAGE_LEN, tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        rc ^= forkskinny_sonicae_verify(&ks, NULL, 0,
                                        dec_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c += c;
            total_ns += timing_cycles_to_ns(c);
        }
    }

    bench_sink32 ^= (uint32_t)rc;

    printk("  %-14s: %10llu cycles | %10llu ns\n",
           "auth-check",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));

    k_msleep(1);
}

/* ── top-level entry point ─────────────────────────────── */
void bench_sonicae_all(void)
{
    printk("[FORKSKINNY SONICAE] Benchmark  msg=%d bytes  iters=%d\n",
           MESSAGE_LEN, BENCH_ITERS);
    printk("  %-14s  %10s  %12s\n", "operation", "cycles", "ns");

    /* keygen bench removed */
    bench_auth();
    bench_encrypt();
    bench_decrypt();
    bench_auth_check();

    printk("--- Benchmark complete ---\n\n");
}