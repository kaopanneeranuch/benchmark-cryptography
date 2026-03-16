/* Bench stubs for SCT Butterknife — placeholder implementations */
#include <zephyr/kernel.h>
#include <zephyr/timing/timing.h>
#include <zephyr/sys/printk.h>

#include "bench.h"

void verify_correctness(void)
{
    printk("--- SCT Butterknife: placeholder correctness check ---\n");
}

void bench_block_encrypt(void)
{
    printk("[SCT-BUTTERKNIFE] Block encrypt benchmark: placeholder\n");
}

void bench_sct_encrypt(void)
{
    printk("[SCT-BUTTERKNIFE] SCT encrypt benchmark: placeholder\n");
}

void bench_sct_decrypt(void)
{
    printk("[SCT-BUTTERKNIFE] SCT decrypt benchmark: placeholder\n");
}
