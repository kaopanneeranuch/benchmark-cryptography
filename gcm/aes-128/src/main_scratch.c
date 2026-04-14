#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include "bench.h"

int main(void)
{
    timing_init();
    timing_start();

    printk("\n=== AES-128 GCM AEAD Benchmark ===\n\n");

    verify_correctness();
    bench_gcm_all();

    timing_stop();

    return 0;
}
