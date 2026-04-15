#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include "bench.h"

void main(void)
{
    timing_init();
    timing_start();

    printk("\n=== Skinny-SCT AEAD Benchmark ===\n\n");

    bench_sct_all();

    timing_stop();
}
