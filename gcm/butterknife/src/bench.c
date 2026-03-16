/* Bench implementation extracted from main.c */
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/timing/timing.h>

#include "utils.h"
#include "gf.h"
#include "ghash.h"
#include "butterknife-gcm.h"
#include "bench.h"

/* ── configuration ──────────────────────────────────────── */
#define WARMUP_ITERS   10
#define BENCH_ITERS   100
#define NUM_SIZES       6
static const size_t data_sizes[NUM_SIZES] = {16, 64, 128, 256, 512, 1024};

/* work buffers (static to avoid stack overflow on small targets) */
static uint8_t pt_buf[1024];
static uint8_t ct_buf[1024];
static uint8_t dec_buf[1024];
static uint8_t tag_buf[16];

static const uint8_t bench_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t bench_nonce[12] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab
};

/* ── helpers ────────────────────────────────────────────── */
static void print_hex(const char *label, const uint8_t *buf, size_t n)
{
    printk("%s", label);
    for (size_t i = 0; i < n; i++) printk("%02x", buf[i]);
    printk("\n");
}

static void fill_pattern(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }
}

/* ── correctness check (runs once) ──────────────────────── */
void verify_correctness(void)
{
    const uint8_t plaintext[] = "Hello World!";
    const size_t len = strlen((const char *)plaintext);
    uint8_t ct[64] = {0}, tag[16] = {0}, dec[64] = {0};

    printk("--- Correctness Check ---\n");
    butterknife_gcm_encrypt(bench_key, bench_nonce, NULL, 0, plaintext, len, ct, tag);
    printk("PT:  %s\n", plaintext);
    print_hex("CT:  ", ct, len);
    print_hex("TAG: ", tag, 16);

    if (butterknife_gcm_decrypt(bench_key, bench_nonce, NULL, 0, ct, len, tag, dec) != 0) {
        printk("Decryption/verification FAILED!\n");
        return;
    }
    dec[len] = '\0';
    printk("DEC: %s\n", dec);
    printk("--- OK ---\n\n");
}

/* ── benchmark routines ─────────────────────────────────── */
void bench_block_encrypt(void)
{
    uint8_t in[16] = {0};
    uint8_t out[16];
    timing_t start, end;
    uint64_t total_cycles = 0;
    uint64_t total_ns = 0;

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        butterknife_encrypt_block(bench_key, in, out);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        start = timing_counter_get();
        butterknife_encrypt_block(bench_key, in, out);
        end = timing_counter_get();
        total_cycles += timing_cycles_get(&start, &end);
        total_ns     += timing_cycles_to_ns(timing_cycles_get(&start, &end));
    }

    uint64_t avg_cycles = total_cycles / BENCH_ITERS;
    uint64_t avg_ns     = total_ns / BENCH_ITERS;
    printk("[BUTTERKNIFE] Block Encrypt (1 block):  %llu cycles  |  %llu ns\n",
           (unsigned long long)avg_cycles, (unsigned long long)avg_ns);
}

void bench_gcm_encrypt(void)
{
    timing_t start, end;

    printk("[BUTTERKNIFE-GCM] Encrypt  (%d iterations)\n", BENCH_ITERS);
    printk("  %6s  %12s  %12s  %12s\n", "bytes", "cycles", "ns", "cycles/byte");

    for (int s = 0; s < NUM_SIZES; s++) {
        size_t len = data_sizes[s];
        fill_pattern(pt_buf, len);
        uint64_t total_cycles = 0;
        uint64_t total_ns = 0;

        /* warm-up */
        for (int i = 0; i < WARMUP_ITERS; i++) {
            butterknife_gcm_encrypt(bench_key, bench_nonce, NULL, 0,
                                    pt_buf, len, ct_buf, tag_buf);
        }

        for (int i = 0; i < BENCH_ITERS; i++) {
            start = timing_counter_get();
            butterknife_gcm_encrypt(bench_key, bench_nonce, NULL, 0,
                                    pt_buf, len, ct_buf, tag_buf);
            end = timing_counter_get();
            total_cycles += timing_cycles_get(&start, &end);
            total_ns     += timing_cycles_to_ns(timing_cycles_get(&start, &end));
        }

        uint64_t avg_cycles = total_cycles / BENCH_ITERS;
        uint64_t avg_ns     = total_ns / BENCH_ITERS;
        uint64_t cpb        = avg_cycles / (uint64_t)len;
        printk("  %6zu  %12llu  %12llu  %12llu\n", len,
               (unsigned long long)avg_cycles,
               (unsigned long long)avg_ns,
               (unsigned long long)cpb);
    }
}

void bench_gcm_decrypt(void)
{
    timing_t start, end;

    printk("[BUTTERKNIFE-GCM] Decrypt  (%d iterations)\n", BENCH_ITERS);
    printk("  %6s  %12s  %12s  %12s\n", "bytes", "cycles", "ns", "cycles/byte");

    for (int s = 0; s < NUM_SIZES; s++) {
        size_t len = data_sizes[s];
        fill_pattern(pt_buf, len);

        /* produce valid ciphertext + tag first */
        butterknife_gcm_encrypt(bench_key, bench_nonce, NULL, 0,
                                pt_buf, len, ct_buf, tag_buf);

        uint64_t total_cycles = 0;
        uint64_t total_ns = 0;

        /* warm-up */
        for (int i = 0; i < WARMUP_ITERS; i++) {
            butterknife_gcm_decrypt(bench_key, bench_nonce, NULL, 0,
                                    ct_buf, len, tag_buf, dec_buf);
        }

        for (int i = 0; i < BENCH_ITERS; i++) {
            start = timing_counter_get();
            butterknife_gcm_decrypt(bench_key, bench_nonce, NULL, 0,
                                    ct_buf, len, tag_buf, dec_buf);
            end = timing_counter_get();
            total_cycles += timing_cycles_get(&start, &end);
            total_ns     += timing_cycles_to_ns(timing_cycles_get(&start, &end));
        }

        uint64_t avg_cycles = total_cycles / BENCH_ITERS;
        uint64_t avg_ns     = total_ns / BENCH_ITERS;
        uint64_t cpb        = avg_cycles / (uint64_t)len;
        printk("  %6zu  %12llu  %12llu  %12llu\n", len,
               (unsigned long long)avg_cycles,
               (unsigned long long)avg_ns,
               (unsigned long long)cpb);
    }
}
