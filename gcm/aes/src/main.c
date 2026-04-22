#include <psa/crypto.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include "bench.h"

int main(void)
{
    timing_init();
    timing_start();
    psa_crypto_init();

    printk("\n=== AES-GCM & Rijndael-256-GCM Benchmark (3-cipher version) ===\n\n");
    printk("  [1] AES-128-GCM (128-bit block, 128-bit key)\n");
    printk("  [2] AES-256-GCM (128-bit block, 256-bit key)\n");
    printk("  [3] Rijndael-256-GCM (256-bit block, 256-bit key)\n\n");

    verify_correctness();
    bench_gcm_all();

    timing_stop();
    return 0;
}
