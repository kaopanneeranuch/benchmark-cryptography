#ifndef SCT_BUTTERKNIFE_BENCH_H
#define SCT_BUTTERKNIFE_BENCH_H

#include <stddef.h>
#include <stdint.h>

void verify_correctness(void);
void bench_block_encrypt(void);
void bench_sct_encrypt(void);
void bench_sct_decrypt(void);

#endif /* SCT_BUTTERKNIFE_BENCH_H */
