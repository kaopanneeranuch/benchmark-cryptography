#ifndef AES_BENCH_H
#define AES_BENCH_H

void verify_correctness(void);
void bench_block_encrypt(void);
void bench_gcm_encrypt(void);
void bench_gcm_decrypt(void);

#endif /* AES_BENCH_H */
