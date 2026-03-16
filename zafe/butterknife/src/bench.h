#ifndef BUTTERKNIFE_ZAFE_BENCH_H
#define BUTTERKNIFE_ZAFE_BENCH_H

#include <stddef.h>
#include <stdint.h>

void verify_correctness(void);
void bench_block_encrypt(void);
void bench_zafe_encrypt(void);
void bench_zafe_decrypt(void);

#endif /* BUTTERKNIFE_ZAFE_BENCH_H */
