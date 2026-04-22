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

    printk("\n=== AES-GCM Benchmark (flat 5-file version) ===\n\n");

    verify_correctness();
    bench_gcm_all();

    timing_stop();
    return 0;
}
