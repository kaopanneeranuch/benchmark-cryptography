#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include "bench.h"

void main(void)
{
    timing_init();
    timing_start();

    printk("\n=== Skinny-GCM AEAD Benchmark ===\n\n");

    verify_correctness();
    bench_gcm_all();

    timing_stop();
}
