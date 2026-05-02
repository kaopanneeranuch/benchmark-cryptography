#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include "bench.h"

int main(void)
{
    printk("\n=== ForkSkinny-ZAFE AEAD Benchmark ===\n\n");
    bench_zafe_all();
    return 0;
}