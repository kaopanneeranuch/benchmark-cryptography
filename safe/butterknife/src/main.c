/*
 * Butterknife-256  SAFE  (Secure Authenticated Forking Encryption) Benchmark
 *
 * SAFE is a single-pass online AEAD mode that exploits the dual-fork output
 * of Butterknife to simultaneously encrypt and accumulate authentication
 * in ONE TBC call per message block:
 *
 *   (S_i, A_i) = BK_K^{enc||i||N}(0^n)   [branch 1=keystream, branch 2=auth]
 *   C_i = M_i ^ S_i                         (CTR encryption)
 *   sigma ^= (A_i ^ M_i)                    (MAC accumulation)
 *
 *   Tag = BK_K^{tag||0||N}(sigma)            [1-branch only]
 *
 * Tweak layout (16 bytes):
 *   [domain(4b) | counter(28b)]  [nonce(12B)]
 *
 * Domain assignments:
 *   0x4  enc full block  (both branches)
 *   0x5  enc partial     (both branches, 10* pad for auth)
 *   0x1  tag finalize    (1 branch only)
 *
 * Measures:
 *   - Layer 1: Single tweakable block encrypt (1 branch)
 *   - Layer 1: Single tweakable block fork    (2 branches)
 *   - Layer 3: SAFE Encrypt   (multiple data sizes)
 *   - Layer 3: SAFE Decrypt   (with tag verification)
 *   - Correctness check with PT / CT / TAG / DEC output
 */
#include <zephyr/kernel.h>
#include <zephyr/timing/timing.h>

#include "butterknife_safe.h"
#include "bench.h"

int main(void)
{
    timing_init();
    timing_start();

    printk("\n========================================\n");
    printk("  Butterknife SAFE Benchmark\n");
    printk("  (Single-pass AE with dual fork)\n");
    printk("  Iterations: %d  |  Warm-up: %d\n", 100, 10);
    printk("========================================\n\n");

    verify_correctness();
    bench_block_encrypt();
    bench_block_fork();
    printk("\n");
    bench_safe_encrypt();
    printk("\n");
    bench_safe_decrypt();

    printk("\n========================================\n");
    printk("  Butterknife SAFE Benchmark Complete\n");
    printk("========================================\n");

    timing_stop();
    return 0;
}
