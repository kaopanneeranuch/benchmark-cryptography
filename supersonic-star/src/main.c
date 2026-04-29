#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "include/sonics_ref.h"
#include "include/supersonic_fs_star.h"
#include "include/supersonic_bk_star.h"
#include "include/butterknife.h"

#define WARMUP_ITERS 10
#define BENCH_ITERS  100

typedef void (*supersonic_fn_t)(const uint8_t key[16],
                                uint8_t out_left[16],
                                uint8_t out_right[16],
                                const uint8_t *message,
                                const uint32_t mlen);

static uint8_t msg_buf[4096];
static const uint8_t bench_key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
};

static volatile uint8_t sink;

static void fill_pattern(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xffU);
    }
}

static void bench_supersonic_star_variant(supersonic_fn_t fn, uint32_t mlen,
                                          uint64_t *out_cycles, uint64_t *out_ns)
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

    *out_cycles = total_cycles;
    *out_ns     = total_ns;
}

#define TOTAL_ITERS (WARMUP_ITERS + BENCH_ITERS)

/* c1: 1-leg primitive call count (accumulated over TOTAL_ITERS).
 * c2: 2-leg primitive call count (accumulated over TOTAL_ITERS). */
static void print_counters(const char *name1, uint32_t c1,
                           const char *name2, uint32_t c2)
{
    uint32_t l1 = c1 / TOTAL_ITERS;
    uint32_t l2 = 2u * c2 / TOTAL_ITERS;
    if (l2 > 0)
        printk("    [legs/op] %s=%" PRIu32 "  %s=%" PRIu32 "\n",
               name1, l1, name2, l2);
    else
        printk("    [legs/op] %s=%" PRIu32 "\n",
               name1, l1);
}

static void print_variant(const char *name, uint32_t mlen,
                          uint64_t total_cycles, uint64_t total_ns,
                          uint32_t oneleg, uint32_t twoleg)
{
    uint32_t legs_per_op = (oneleg + 2u * twoleg) / TOTAL_ITERS;
    uint64_t denom = (uint64_t)legs_per_op * BENCH_ITERS;

    printk("  %-26s %6u B : %12" PRIu64 " cyc/leg | %12" PRIu64 " ns/leg  [%u legs/op]\n",
           name, mlen,
           denom > 0u ? total_cycles / denom : 0u,
           denom > 0u ? total_ns     / denom : 0u,
           legs_per_op);
}

static void bench_size(uint32_t mlen)
{
    uint32_t oneleg, twoleg;
    uint64_t cyc, ns;

    printk("\n[Message size: %u bytes]\n", mlen);

    supersonic_fs_star_reset_counters();
    bench_supersonic_star_variant(supersonic_256_star, mlen, &cyc, &ns);
    supersonic_fs256_star_get_counters(&oneleg, &twoleg);
    print_variant("supersonic_256_forkskinny", mlen, cyc, ns, oneleg, twoleg);
    print_counters("skinny_r32", oneleg, "forkskinny_256", twoleg);

    supersonic_fs_star_reset_counters();
    bench_supersonic_star_variant(supersonic_384_star, mlen, &cyc, &ns);
    supersonic_fs384_star_get_counters(&oneleg, &twoleg);
    print_variant("supersonic_384_forkskinny", mlen, cyc, ns, oneleg, twoleg);
    print_counters("forkskinny_384_enc", oneleg, "forkskinny_384_fork", twoleg);

    supersonic_bk_deoxys_reset_counters();
    bench_supersonic_star_variant(supersonic_256_butterknife_deoxys, mlen, &cyc, &ns);
    supersonic_bk_deoxys_get_counters(&oneleg, &twoleg);
    print_variant("supersonic_256_bk_deoxys", mlen, cyc, ns, oneleg, twoleg);
    print_counters("deoxysBC", oneleg, "butterknife", twoleg);

    supersonic_bk_deoxys_opt_reset_counters();
    bench_supersonic_star_variant(supersonic_256_butterknife_deoxys_opt, mlen, &cyc, &ns);
    supersonic_bk_deoxys_opt_get_counters(&oneleg, &twoleg);
    print_variant("supersonic_256_bk_deoxys_opt", mlen, cyc, ns, oneleg, twoleg);
    print_counters("deoxysBC_opt", oneleg, "butterknife", twoleg);

    supersonic_bk_skinny_reset_counters();
    bench_supersonic_star_variant(supersonic_256_butterknife_skinny, mlen, &cyc, &ns);
    supersonic_bk_skinny_get_counters(&oneleg, &twoleg);
    print_variant("supersonic_256_bk_skinny", mlen, cyc, ns, oneleg, twoleg);
    print_counters("skinny_r32", oneleg, "butterknife", twoleg);
}

int main(void)
{
    timing_init();
    timing_start();

    printk("\n=== Supersonic Star Benchmark (Deoxys / Butterknife / Skinny) ===\n");
    printk("iters=%d, warmup=%d\n", BENCH_ITERS, WARMUP_ITERS);
    printk("format: <variant> <size> : <cyc/leg> | <ns/leg>  [legs/op]\n");

    bench_size(8);
    bench_size(100);
    bench_size(4096);

    printk("\nBenchmark done (sink=%u).\n", sink);
    return 0;
}