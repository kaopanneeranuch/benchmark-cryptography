#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include <string.h>
#include <stdint.h>

#include "forkskinny_zafe.h"
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
static uint8_t tag_buf[ZAFE_TAG_LEN];

#if AD_LEN > 0
static uint8_t ad_buf[AD_LEN];
#else
static uint8_t *ad_buf = NULL;
#endif

static zafe_key_t ks;

/* 32-byte key: first 16 bytes for enc_key, next 16 bytes for mac_key */
static const uint8_t bench_key[ZAFE_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static void fill_pattern(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xFF);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("%s", label);
    for (size_t i = 0; i < len; i++) {
        printk("%02x", buf[i]);
    }
    printk("\n");
}

/* ── correctness check ─────────────────────────────────── */
void verify_correctness(void)
{
    int rc;

    printk("--- ForkSkinny ZAFE Correctness (msg=%d ad=%d) ---\n",
           MESSAGE_LEN, AD_LEN);

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);

    /* initialize key schedule */
    memcpy(ks.enc_key, bench_key, ZAFE_ENC_KEY_LEN);
    memcpy(ks.mac_key, bench_key + ZAFE_ENC_KEY_LEN, ZAFE_MAC_KEY_LEN);

    rc = forkskinny_zafe_encrypt_auth(&ks,
                                      ad_buf, AD_LEN,
                                      pt_buf, MESSAGE_LEN,
                                      ct_buf, tag_buf);

    printk("Encrypt+Auth:   %s\n", rc == 0 ? "OK" : "FAIL");
    if (rc != 0) {
        printk("--- End correctness ---\n\n");
        return;
    }

    print_hex("PT[0..15]: ", pt_buf, 16);
    print_hex("CT[0..15]: ", ct_buf, 16);
    print_hex("TAG:       ", tag_buf, ZAFE_TAG_LEN);

    rc = forkskinny_zafe_decrypt_verify(&ks,
                                        ad_buf, AD_LEN,
                                        ct_buf, MESSAGE_LEN,
                                        tag_buf, dec_buf);

    print_hex("DEC[0..15]: ", dec_buf, 16);
    printk("Decrypt+Verify: %s\n", rc == 0 ? "OK" : "FAIL");

    if (rc == 0 && memcmp(pt_buf, dec_buf, MESSAGE_LEN) == 0) {
        printk("Plaintext match: OK\n");
    } else {
        printk("Plaintext match: FAIL\n");
    }

    printk("--- End correctness ---\n\n");
}

/* ── individual benchmarks ─────────────────────────────── */


static void bench_hash(void)
{
    timing_t start, end;
    uint64_t total_c = 0, total_ns = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    memcpy(ks.enc_key, bench_key, ZAFE_ENC_KEY_LEN);
    memcpy(ks.mac_key, bench_key + ZAFE_ENC_KEY_LEN, ZAFE_MAC_KEY_LEN);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        (void)forkskinny_zafe_auth(&ks,
                                   ad_buf, AD_LEN,
                                   pt_buf, MESSAGE_LEN,
                                   tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        (void)forkskinny_zafe_auth(&ks,
                                   ad_buf, AD_LEN,
                                   pt_buf, MESSAGE_LEN,
                                   tag_buf);
        end = timing_counter_get();

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c  += c;
            total_ns += timing_cycles_to_ns(c);
        }
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
    fill_pattern(ad_buf, AD_LEN);
    memcpy(ks.enc_key, bench_key, ZAFE_ENC_KEY_LEN);
    memcpy(ks.mac_key, bench_key + ZAFE_ENC_KEY_LEN, ZAFE_MAC_KEY_LEN);

    (void)forkskinny_zafe_auth(&ks,
                               ad_buf, AD_LEN,
                               pt_buf, MESSAGE_LEN,
                               tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        uint8_t tag_local[ZAFE_TAG_LEN];
        memcpy(tag_local, tag_buf, ZAFE_TAG_LEN);
        forkskinny_zafe_encrypt(&ks, tag_local, pt_buf, MESSAGE_LEN, ct_buf);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint8_t tag_local[ZAFE_TAG_LEN];
        memcpy(tag_local, tag_buf, ZAFE_TAG_LEN);

        start = timing_counter_get();
        forkskinny_zafe_encrypt(&ks, tag_local, pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c  += c;
            total_ns += timing_cycles_to_ns(c);
        }
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
    memcpy(ks.enc_key, bench_key, ZAFE_ENC_KEY_LEN);
    memcpy(ks.mac_key, bench_key + ZAFE_ENC_KEY_LEN, ZAFE_MAC_KEY_LEN);

    (void)forkskinny_zafe_encrypt_auth(&ks,
                                       ad_buf, AD_LEN,
                                       pt_buf, MESSAGE_LEN,
                                       ct_buf, tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        uint8_t tag_local[ZAFE_TAG_LEN];
        memcpy(tag_local, tag_buf, ZAFE_TAG_LEN);
        forkskinny_zafe_decrypt(&ks, tag_local, ct_buf, MESSAGE_LEN, dec_buf);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint8_t tag_local[ZAFE_TAG_LEN];
        memcpy(tag_local, tag_buf, ZAFE_TAG_LEN);

        start = timing_counter_get();
        forkskinny_zafe_decrypt(&ks, tag_local, ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c  += c;
            total_ns += timing_cycles_to_ns(c);
        }
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
    fill_pattern(ad_buf, AD_LEN);
    memcpy(ks.enc_key, bench_key, ZAFE_ENC_KEY_LEN);
    memcpy(ks.mac_key, bench_key + ZAFE_ENC_KEY_LEN, ZAFE_MAC_KEY_LEN);

    (void)forkskinny_zafe_auth(&ks,
                               ad_buf, AD_LEN,
                               pt_buf, MESSAGE_LEN,
                               tag_buf);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        (void)forkskinny_zafe_verify(&ks,
                                     ad_buf, AD_LEN,
                                     pt_buf, MESSAGE_LEN,
                                     tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        (void)forkskinny_zafe_verify(&ks,
                                     ad_buf, AD_LEN,
                                     pt_buf, MESSAGE_LEN,
                                     tag_buf);
        end = timing_counter_get();

        {
            uint64_t c = timing_cycles_get(&start, &end);
            total_c  += c;
            total_ns += timing_cycles_to_ns(c);
        }
    }

    printk("  %-14s: %10llu cycles  |  %10llu ns\n", "verify",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
}

/* ── top-level entry ───────────────────────────────────── */
void bench_zafe_all(void)
{
    timing_init();
    timing_start();

    printk("[FORKSKINNY ZAFE] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  %-14s  %10s  %12s\n", "operation", "cycles", "ns");

    verify_correctness();

    bench_hash();
    bench_encrypt();
    bench_decrypt();
    bench_verify();

    timing_stop();

    printk("--- Benchmark complete ---\n\n");
}