#include <zephyr/kernel.h>
#include <zephyr/timing/timing.h>

#include "bench.h"

int main(void)
{
        timing_init();
        timing_start();

        printk("\n========================================\n");
        printk("  SCT Butterknife Benchmark (placeholder)\n");
        printk("========================================\n\n");

        verify_correctness();
        bench_block_encrypt();
        printk("\n");
        bench_sct_encrypt();
        printk("\n");
        bench_sct_decrypt();

        printk("\n========================================\n");
        printk("  SCT Butterknife Benchmark Complete\n");
        printk("========================================\n");

        timing_stop();
        return 0;
}
