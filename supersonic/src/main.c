#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "include/gctr3.h"
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
static uint8_t dec_buf[4096];
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
        printk("    [leg/op] %s=%" PRIu32 "  %s=%" PRIu32 "\n",
               name1, c1 / TOTAL_ITERS, name2, c2 / TOTAL_ITERS);
    else
        printk("    [leg/op] %s=%" PRIu32 "\n",
               name1, c1 / TOTAL_ITERS);
}

static void fill_pattern(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xffU);
    }
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printk("    %-22s:", label);
    for (size_t i = 0; i < len; ++i)
        printk(" %02x", data[i]);
    printk("\n");
}

/* ---- correctness: GCTR-3 encrypt/decrypt roundtrip --------------------- */

static void check_gctr3_correctness(void)
{
    static uint8_t pt[64];
    static uint8_t ct[64];
    static uint8_t rt[64];

    fill_pattern(pt, 64);

    printk("  gctr3_forkskinny:\n");
    gctr_3_forkskinny(bench_key, gctr_r, gctr_n, pt, 64, ct);
    print_hex("ct (first 16 B)", ct, 16);
    gctr_3_forkskinny(bench_key, gctr_r, gctr_n, ct, 64, rt);
    printk("    decrypt: %s\n", memcmp(pt, rt, 64) == 0 ? "[PASS]" : "[FAIL]");

    printk("  gctr3_butterknife:\n");
    gctr_3_butterknife_iv_full(bench_key, gctr_iv, pt, 64, ct);
    print_hex("ct (first 16 B)", ct, 16);
    gctr_3_butterknife_iv_full(bench_key, gctr_iv, ct, 64, rt);
    printk("    decrypt: %s\n", memcmp(pt, rt, 64) == 0 ? "[PASS]" : "[FAIL]");

    printk("  gctr3_prime_forkskinny:\n");
    gctr_3_prime(bench_key, gctr_tag, pt, 64, ct);
    print_hex("ct (first 16 B)", ct, 16);
    gctr_3_prime(bench_key, gctr_tag, ct, 64, rt);
    printk("    decrypt: %s\n", memcmp(pt, rt, 64) == 0 ? "[PASS]" : "[FAIL]");

    printk("  gctr3_prime_butterknife:\n");
    gctr_3_prime_butterknife(bench_key, gctr_tag, pt, 64, ct);
    print_hex("ct (first 16 B)", ct, 16);
    gctr_3_prime_butterknife(bench_key, gctr_tag, ct, 64, rt);
    printk("    decrypt: %s\n", memcmp(pt, rt, 64) == 0 ? "[PASS]" : "[FAIL]");
}

/* ---- correctness: supersonic tag verify -------------------------------- */

static void check_supersonic_correctness(void)
{
    static uint8_t msg[64];
    uint8_t tl[16], tr[16], cl[16], cr[16];
    int match;

    fill_pattern(msg, 64);

    /* supersonic_256_forkskinny */
    printk("  supersonic_256_forkskinny:\n");
    supersonic_256_forkskinny(bench_key, tl, tr, msg, 64);
    print_hex("tag_L", tl, 16);
    print_hex("tag_R", tr, 16);

    supersonic_256_forkskinny(bench_key, cl, cr, msg, 64);
    match = (memcmp(tl, cl, 16) == 0 && memcmp(tr, cr, 16) == 0);
    printk("    verify(same msg):    %s\n", match ? "[PASS] MATCH" : "[FAIL] MISMATCH");

    msg[0] ^= 0xff;
    supersonic_256_forkskinny(bench_key, cl, cr, msg, 64);
    match = (memcmp(tl, cl, 16) == 0 && memcmp(tr, cr, 16) == 0);
    printk("    verify(tampered):    %s\n", !match ? "[PASS] MISMATCH (correct)" : "[FAIL] still MATCH");
    msg[0] ^= 0xff;

    /* supersonic_256_butterknife */
    printk("  supersonic_256_butterknife:\n");
    supersonic_256_butterknife(bench_key, tl, tr, msg, 64);
    print_hex("tag_L", tl, 16);
    print_hex("tag_R", tr, 16);

    supersonic_256_butterknife(bench_key, cl, cr, msg, 64);
    match = (memcmp(tl, cl, 16) == 0 && memcmp(tr, cr, 16) == 0);
    printk("    verify(same msg):    %s\n", match ? "[PASS] MATCH" : "[FAIL] MISMATCH");

    msg[0] ^= 0xff;
    supersonic_256_butterknife(bench_key, cl, cr, msg, 64);
    match = (memcmp(tl, cl, 16) == 0 && memcmp(tr, cr, 16) == 0);
    printk("    verify(tampered):    %s\n", !match ? "[PASS] MISMATCH (correct)" : "[FAIL] still MATCH");
    msg[0] ^= 0xff;
}

/* ---- bench: supersonic tag verify (recompute + compare) ---------------- */

static void bench_supersonic_verify(uint32_t mlen)
{
    timing_t start;
    timing_t end;
    uint64_t total_cycles;
    uint64_t total_ns;
    uint8_t ref_l[16], ref_r[16];
    uint8_t chk_l[16], chk_r[16];
    volatile uint8_t match;
    uint32_t c1leg, c2leg;

    fill_pattern(msg_buf, mlen);

    /* --- supersonic_256_forkskinny verify --- */
    supersonic_256_forkskinny(bench_key, ref_l, ref_r, msg_buf, mlen);

    total_cycles = 0; total_ns = 0;
    forkskinny_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        supersonic_256_forkskinny(bench_key, chk_l, chk_r, msg_buf, mlen);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        supersonic_256_forkskinny(bench_key, chk_l, chk_r, msg_buf, mlen);
        match = (memcmp(ref_l, chk_l, 16) == 0 && memcmp(ref_r, chk_r, 16) == 0) ? 1u : 0u;
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= match;
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "supersonic_256_fs_verify", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           g_fs128_256_legs       / TOTAL_ITERS,
           g_fs128_256_1leg_calls / TOTAL_ITERS,
           g_fs128_256_2leg_calls / TOTAL_ITERS);
    k_msleep(1);

    /* --- supersonic_256_butterknife verify --- */
    supersonic_256_butterknife(bench_key, ref_l, ref_r, msg_buf, mlen);

    total_cycles = 0; total_ns = 0;
    supersonic_bk_reset_counters();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        supersonic_256_butterknife(bench_key, chk_l, chk_r, msg_buf, mlen);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        supersonic_256_butterknife(bench_key, chk_l, chk_r, msg_buf, mlen);
        match = (memcmp(ref_l, chk_l, 16) == 0 && memcmp(ref_r, chk_r, 16) == 0) ? 1u : 0u;
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= match;
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "supersonic_256_bk_verify", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    supersonic_bk_get_counters(&c1leg, &c2leg);
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           (c1leg + 2u * c2leg) / TOTAL_ITERS,
           c1leg / TOTAL_ITERS,
           c2leg / TOTAL_ITERS);
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
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           g_fs128_256_legs       / TOTAL_ITERS,
           g_fs128_256_1leg_calls / TOTAL_ITERS,
           g_fs128_256_2leg_calls / TOTAL_ITERS);
    k_msleep(1);

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
    k_msleep(1);

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
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           g_fs128_256_legs       / TOTAL_ITERS,
           g_fs128_256_1leg_calls / TOTAL_ITERS,
           g_fs128_256_2leg_calls / TOTAL_ITERS);
    k_msleep(1);

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

static void bench_gctr_decrypt_variants(uint32_t mlen)
{
    timing_t start;
    timing_t end;
    uint64_t total_cycles;
    uint64_t total_ns;

    fill_pattern(msg_buf, mlen);

    /* gctr3_forkskinny decrypt */
    gctr_3_forkskinny(bench_key, gctr_r, gctr_n, msg_buf, mlen, out_buf);
    total_cycles = 0; total_ns = 0;
    forkskinny_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_forkskinny(bench_key, gctr_r, gctr_n, out_buf, mlen, dec_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_forkskinny(bench_key, gctr_r, gctr_n, out_buf, mlen, dec_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= dec_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_fs_decrypt", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           g_fs128_256_legs       / TOTAL_ITERS,
           g_fs128_256_1leg_calls / TOTAL_ITERS,
           g_fs128_256_2leg_calls / TOTAL_ITERS);
    k_msleep(1);

    /* gctr3_butterknife decrypt */
    gctr_3_butterknife_iv_full(bench_key, gctr_iv, msg_buf, mlen, out_buf);
    total_cycles = 0; total_ns = 0;
    butterknife_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_butterknife_iv_full(bench_key, gctr_iv, out_buf, mlen, dec_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_butterknife_iv_full(bench_key, gctr_iv, out_buf, mlen, dec_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= dec_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_bk_decrypt", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    print_counters("butterknife", g_butterknife_256_enc_calls, "", 0);
    k_msleep(1);

    /* gctr3_prime_forkskinny decrypt */
    gctr_3_prime(bench_key, gctr_tag, msg_buf, mlen, out_buf);
    total_cycles = 0; total_ns = 0;
    forkskinny_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_prime(bench_key, gctr_tag, out_buf, mlen, dec_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_prime(bench_key, gctr_tag, out_buf, mlen, dec_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= dec_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_prime_fs_decrypt", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           g_fs128_256_legs       / TOTAL_ITERS,
           g_fs128_256_1leg_calls / TOTAL_ITERS,
           g_fs128_256_2leg_calls / TOTAL_ITERS);
    k_msleep(1);

    /* gctr3_prime_butterknife decrypt */
    gctr_3_prime_butterknife(bench_key, gctr_tag, msg_buf, mlen, out_buf);
    total_cycles = 0; total_ns = 0;
    butterknife_counters_reset();
    for (int i = 0; i < WARMUP_ITERS; ++i)
        gctr_3_prime_butterknife(bench_key, gctr_tag, out_buf, mlen, dec_buf);
    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        gctr_3_prime_butterknife(bench_key, gctr_tag, out_buf, mlen, dec_buf);
        end = timing_counter_get();
        uint64_t cycles = timing_cycles_get(&start, &end);
        total_cycles += cycles;
        total_ns += timing_cycles_to_ns(cycles);
    }
    sink ^= dec_buf[0];
    printk("  %-26s %6u B : %12" PRIu64 " cycles | %12" PRIu64 " ns\n",
           "gctr3_prime_bk_decrypt", mlen,
           total_cycles / BENCH_ITERS, total_ns / BENCH_ITERS);
    print_counters("butterknife", g_butterknife_256_enc_calls, "", 0);
}

static void bench_size(uint32_t mlen)
{
    uint32_t c1leg, c2leg;

    printk("\n[Message size: %u bytes]\n", mlen);

    forkskinny_counters_reset();
    bench_supersonic_variant("supersonic_256_forkskinny", supersonic_256_forkskinny, mlen);
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           g_fs128_256_legs       / TOTAL_ITERS,
           g_fs128_256_1leg_calls / TOTAL_ITERS,
           g_fs128_256_2leg_calls / TOTAL_ITERS);
    k_msleep(1);

    supersonic_bk_reset_counters();
    bench_supersonic_variant("supersonic_256_butterknife", supersonic_256_butterknife, mlen);
    supersonic_bk_get_counters(&c1leg, &c2leg);
    printk("    [leg/op] legs=%" PRIu32 "  (1-leg=%" PRIu32 "  2-leg=%" PRIu32 ")\n",
           (c1leg + 2u * c2leg) / TOTAL_ITERS,
           c1leg / TOTAL_ITERS,
           c2leg / TOTAL_ITERS);
    k_msleep(1);

    bench_gctr_variants(mlen);
    bench_gctr_decrypt_variants(mlen);
    bench_supersonic_verify(mlen);
}

int main(void)
{
    timing_init();
    timing_start();

    printk("\n=== Supersonic/GCTR3 Benchmark ===\n");
    printk("iters=%d, warmup=%d\n", BENCH_ITERS, WARMUP_ITERS);
    printk("format: <variant> <size> : <avg cycles> | <avg ns>\n");

    printk("\n[Correctness checks]\n");
    check_gctr3_correctness();
    check_supersonic_correctness();

    bench_size(8);
    bench_size(100);
    bench_size(4096);

    printk("\nBenchmark done (sink=%u).\n", sink);
    return 0;
}