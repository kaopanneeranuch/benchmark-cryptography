#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "include/sonics_ref.h"

#define WARMUP_ITERS 20
#define BENCH_ITERS  200
#define MAX_MSG_LEN  4096

typedef void (*supersonic_fn_t)(const uint8_t key[16],
								uint8_t out_left[16],
								uint8_t out_right[16],
								const uint8_t *message,
								const uint32_t mlen);

static uint8_t msg_buf[MAX_MSG_LEN];
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

static void bench_variant(const char *name, supersonic_fn_t fn, uint32_t mlen)
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

static void bench_size(uint32_t mlen)
{
	printk("\n[Message size: %u bytes]\n", mlen);
	bench_variant("supersonic_256_butterknife", supersonic_256_butterknife, mlen);
	bench_variant("supersonic_256_forkskinny", supersonic_256_forkskinny, mlen);
}

int main(void)
{
	timing_init();
	timing_start();

	printk("\n=== Supersonic Benchmark ===\n");
	printk("iters=%d, warmup=%d\n", BENCH_ITERS, WARMUP_ITERS);
	printk("format: <variant> <size> : <avg cycles> | <avg ns>\n");

	bench_size(8);
	bench_size(100);
	bench_size(4096);

	printk("\nBenchmark done (sink=%u).\n", sink);
	return 0;
}
