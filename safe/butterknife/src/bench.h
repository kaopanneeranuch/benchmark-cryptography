#ifndef BUTTERKNIFE_SAFE_BENCH_H
#define BUTTERKNIFE_SAFE_BENCH_H

#include <stddef.h>
#include <stdint.h>

void verify_correctness(void);
void bench_block_encrypt(void);
void bench_block_fork(void);
void bench_safe_encrypt(void);
void bench_safe_decrypt(void);

#endif /* BUTTERKNIFE_SAFE_BENCH_H */
