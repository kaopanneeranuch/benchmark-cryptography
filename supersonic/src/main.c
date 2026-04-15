#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "gctr-3-bk.h"
#include "gctr-3-fs.h"
#include "gctr-3-prime.h"
#include "gctr-3-prime-bk.h"
#include "include/sonics_ref.h"
#include "include/supersonic.h"
#include "butterknife.h"

#define WARMUP_ITERS  10
#define BENCH_ITERS  100
#define MAX_MSG_LEN  4096
#define TOTAL_ITERS  (WARMUP_ITERS + BENCH_ITERS)

typedef void (*supersonic_fn_t)(const uint8_t key[16],
                                uint8_t out_left[16],
                                uint8_t out_right[16],
                                const uint8_t *message,
                                const uint32_t mlen);

static uint8_t msg_buf[4096];
static uint8_t out_buf[4096];
static const uint8_t bench_key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t gctr_r[16] = {
    0xa0, 0xa1, 0xa2, 0xa3,
    0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab,
    0xac, 0xad, 0xae, 0xaf
};
static const uint8_t gctr_n[16] = {
    0xb0, 0xb1, 0xb2, 0xb3,
    0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb,
    0xbc, 0xbd, 0xbe, 0xbf
};
static const uint8_t gctr_iv[32] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};
/* For GCTR-3-prime, use tag = R || N */
static const uint8_t gctr_tag[32] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};

static volatile uint8_t sink;

static void print_counters(const char *name1, uint32_t c1,
                           const char *name2, uint32_t c2)
{
    if (c2 > 0)
        printk("    [prim/op] %s=%" PRIu32 "  %s=%" PRIu32 "\n",
               name1, c1 / TOTAL_ITERS, name2, c2 / TOTAL_ITERS);
    else
        printk("    [prim/op] %s=%" PRIu32 "\n",
               name1, c1 / TOTAL_ITERS);
}

static void fill_pattern(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xffU);
    }
}

static void bench_supersonic_variant(const char *name, supersonic_fn_t fn, uint32_t mlen)
{
    timing_t start;
    timing_t end;
    uint64_t total_cycles = 0;
    uint64_t total_ns = 0;
    uint8_t out_left[16];
    uint8_t out_right[16];

    fill_pattern(msg_buf, mlen);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        fn(bench_key, out_left, out_right, msg_buf, mlen);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        fn(bench_key, out_left, out_right, msg_buf, mlen);
        end = timing_counter_get();

        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }

    sink ^= out_left[0] ^ out_right[0];

    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           name,
           mlen,
           total_cycles / BENCH_ITERS,
           total_ns / BENCH_ITERS);
}

static void bench_gctr_variants(uint32_t mlen)
{
    timing_t start;
    timing_t end;
    uint64_t total_cycles;
    uint64_t total_ns;

    fill_pattern(msg_buf, mlen);

    /* gctr3_forkskinny */
    total_cycles = 0; total_ns = 0;
    forkskinny_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_forkskinny(bench_key, gctr_r, gctr_n, msg_buf, mlen, out_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_forkskinny(bench_key, gctr_r, gctr_n, msg_buf, mlen, out_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= out_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_forkskinny", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    print_counters("fs_enc", g_fs128_256_enc_calls, "fs_dec", g_fs128_256_dec_calls);

    /* gctr3_butterknife */
    total_cycles = 0; total_ns = 0;
    butterknife_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_butterknife_iv_full(bench_key, gctr_iv, msg_buf, mlen, out_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_butterknife_iv_full(bench_key, gctr_iv, msg_buf, mlen, out_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= out_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_butterknife", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    print_counters("butterknife", g_butterknife_256_enc_calls, "", 0);

    /* gctr3_prime_forkskinny */
    total_cycles = 0; total_ns = 0;
    forkskinny_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_prime(bench_key, gctr_tag, msg_buf, mlen, out_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_prime(bench_key, gctr_tag, msg_buf, mlen, out_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= out_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_prime_forkskinny", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    print_counters("fs_enc", g_fs128_256_enc_calls, "fs_dec", g_fs128_256_dec_calls);

    /* gctr3_prime_butterknife */
    total_cycles = 0; total_ns = 0;
    butterknife_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_prime_butterknife(bench_key, gctr_tag, msg_buf, mlen, out_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_prime_butterknife(bench_key, gctr_tag, msg_buf, mlen, out_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= out_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_prime_butterknife", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    print_counters("butterknife", g_butterknife_256_enc_calls, "", 0);
}

static void bench_size(uint32_t mlen)
{
    uint32_t c1leg, c2leg;

    printk("\n[Message size: %u bytes]\n", mlen);

    supersonic_bk_reset_counters();
    bench_supersonic_variant("supersonic_256_butterknife", supersonic_256_butterknife, mlen);
    supersonic_bk_get_counters(&c1leg, &c2leg);
    print_counters("deoxysBC", c1leg, "butterknife", c2leg);

    forkskinny_counters_reset();
    bench_supersonic_variant("supersonic_256_forkskinny", supersonic_256_forkskinny, mlen);
    print_counters("fs_enc", g_fs128_256_enc_calls, "fs_dec", g_fs128_256_dec_calls);

    bench_gctr_variants(mlen);
}

int main(void)
{
    timing_init();
    timing_start();

    printk("\n=== Supersonic/GCTR3 Benchmark ===\n");
    printk("iters=%d, warmup=%d\n", BENCH_ITERS, WARMUP_ITERS);
    printk("format: <variant> <size> : <avg cycles> | <avg ns>\n");

    bench_size(8);
    bench_size(100);
    bench_size(4096);

    printk("\nBenchmark done (sink=%u).\n", sink);
    return 0;
}