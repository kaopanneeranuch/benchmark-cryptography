/*
 * Butterknife-256  ZAFE  (Zero-misuse AE with Forking Encryption) Benchmark
 *
 * ZAFE is a two-pass, nonce-misuse resistant AEAD mode for tweakable
 * block ciphers, comparable to AES-GCM-SIV:
 *
 *   Pass 1 – Authenticate (PMAC-like hash of plaintext → Tag):
 *       H_i     = E_K^{hash||i||N}(M_i)              (full blocks)
 *       H*      = E_K^{hpart||j||N}(M*||10*)          (partial block)
 *       sigma   = XOR of all H_i
 *       Tag     = E_K^{tag||0||N}(sigma)
 *
 *   Pass 2 – Encrypt (CTR with Tag embedded in tweak):
 *       S_i = E_K^{enc||i||Tag12}(0^n)
 *       C_i = M_i ^ S_i
 *
 * All TBC calls use 1 branch of Butterknife-256.
 *
 * Tweak layout (16 bytes):
 *   [domain(4b) | counter(28b)]  [aux(12B): nonce or tag[0..11]]
 *
 * Domain assignments:
 *   0x8  hash full block       (1 branch, aux=nonce)
 *   0xA  hash partial block    (1 branch, aux=nonce, 10* pad)
 *   0x9  tag finalisation      (1 branch, aux=nonce)
 *   0xC  encrypt full block    (1 branch, aux=tag12)
 *   0xD  encrypt partial block (1 branch, aux=tag12)
 *
 * Measures:
 *   - Layer 1: Single tweakable block encrypt (1 branch)
 *   - Layer 3: ZAFE Encrypt (multiple data sizes)
 *   - Layer 3: ZAFE Decrypt (with tag verification)
 *   - Correctness check with PT / CT / TAG / DEC output
 */
#include <zephyr/kernel.h>
#include <zephyr/timing/timing.h>

#include "butterknife_zafe.h"
#include "bench.h"

int main(void)
{
    timing_init();
    timing_start();

    printk("\n========================================\n");
    printk("  Butterknife ZAFE Benchmark\n");
    printk("  (Two-pass SIV-like, nonce-misuse resistant)\n");
    printk("  Iterations: %d  |  Warm-up: %d\n", 100, 10);
    printk("========================================\n\n");

    verify_correctness();
    bench_block_encrypt();
    printk("\n");
    bench_zafe_encrypt();
    printk("\n");
    bench_zafe_decrypt();

    printk("\n========================================\n");
    printk("  Butterknife ZAFE Benchmark Complete\n");
    printk("========================================\n");

    timing_stop();
    return 0;
}
