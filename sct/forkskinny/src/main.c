#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include "bench.h"

int main(void)
{
    timing_init();
    timing_start();

    printk("\n========================================\n");
    printk("  ForkSkinny-SCT Benchmark (Deoxys-II style)\n");
    printk("========================================\n\n");

    verify_correctness();
    bench_block_encrypt();
    printk("\n");
    bench_sct_encrypt();

    printk("\n========================================\n");
    printk("  ForkSkinny-SCT Benchmark Complete\n");
    printk("========================================\n");

    timing_stop();
    return 0;
}
int main(void)
{
    timing_init();
    timing_start();

    printk("\n========================================\n");
    printk("  ForkSkinny-SCT Benchmark (Deoxys-II style)\n");
    printk("  Iterations: %d  |  Warm-up: %d\n", BENCH_ITERS, WARMUP_ITERS);
    printk("========================================\n\n");

    verify_correctness();
    bench_block_encrypt();
    printk("\n");
    bench_sct_encrypt();

    printk("\n========================================\n");
    printk("  ForkSkinny-SCT Benchmark Complete\n");
    printk("========================================\n");

    timing_stop();
    return 0;
}
