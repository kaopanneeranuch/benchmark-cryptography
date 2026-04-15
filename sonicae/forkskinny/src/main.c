#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include "bench.h"

int main(void)
{
    timing_init();
    timing_start();

    printk("\n=== ForkSkinny-Sonicae AEAD Benchmark ===\n\n");

    bench_sonicae_all();

    timing_stop();
    return 0;
}