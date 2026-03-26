#ifndef SONICS_REF
#define SONICS_REF
#include <stdint.h>
#include "internal-forkskinny.h"

#define SONICS_192_N_SIZE  8
#define SONICS_192_K_SIZE 16
#define SONICS_192_T_SIZE  7
#define SONICS_192_P_SIZE (SONICS_192_N_SIZE + SONICS_192_K_SIZE + SONICS_192_T_SIZE)

#define SONICS_256_N_SIZE 16
#define SONICS_256_K_SIZE 16
#define SONICS_256_T_SIZE 15
#define SONICS_256_P_SIZE (SONICS_256_N_SIZE + SONICS_256_K_SIZE + SONICS_256_T_SIZE)

#define SONICS_384_N_SIZE 16
#define SONICS_384_K_SIZE 16
#define SONICS_384_T_SIZE 31
#define SONICS_384_P_SIZE (SONICS_384_N_SIZE + SONICS_384_K_SIZE + SONICS_384_T_SIZE)

#define SONICS_END_OF_MESSAGE 0x80
#define BABYSONIC_A 8

typedef struct {
    uint8_t kt[SONICS_384_K_SIZE + SONICS_384_T_SIZE + 1];
    uint8_t m[SONICS_384_N_SIZE];
} SonicChains;

typedef struct {
    forkskinny_128_384_tweakey_schedule_t *fs_tks1;
    forkskinny_128_384_tweakey_schedule_t *fs_tks2;
    forkskinny_128_384_tweakey_schedule_t *fs_tks3;
    uint8_t *K_prime;
    uint8_t *mask;
    uint8_t P[SONICS_384_P_SIZE+1];
} Sonics_384_struct_t;

typedef struct {
    forkskinny_128_256_tweakey_schedule_t *fs_tks1;
    forkskinny_128_256_tweakey_schedule_t *fs_tks2;
    uint32_t *bk_rtk;
    uint8_t *K_prime;
    uint8_t *mask;
    uint8_t P[SONICS_256_P_SIZE+1];
} Sonics_256_struct_t;

typedef struct {
    forkskinny_64_192_tweakey_schedule_t *fs_tks1;
    forkskinny_64_192_tweakey_schedule_t *fs_tks2;
    uint8_t *K_prime;
    uint8_t *mask;
    uint8_t P[SONICS_192_P_SIZE+1];
} Sonics_192_struct_t;

/* Butterknife BC */
void supersonic_256_butterknife(const uint8_t key[16], 
                                uint8_t out_left[16], uint8_t out_right[16], 
                                const uint8_t *message, const uint32_t mlen);

void darksonic_256_butterknife(const uint8_t key[16], const uint8_t nonce[16],
                               uint8_t out_left[16], uint8_t out_right[16], 
                               const uint8_t *message, const uint32_t mlen);

void babysonic_256_butterknife(const uint8_t key[16], 
                               uint8_t out_left[16], uint8_t out_right[16], 
                               const uint8_t *message, const uint32_t mlen);

/* Forkskinny BC */
void supersonic_384_forkskinny(const uint8_t key[16], 
                               uint8_t out_left[16], uint8_t out_right[16], 
                               const uint8_t *message, const uint32_t mlen);
void supersonic_256_forkskinny(const uint8_t key[16], 
                               uint8_t out_left[16], uint8_t out_right[16], 
                               const uint8_t *message, const uint32_t mlen);
void supersonic_192_forkskinny(const uint8_t key[16], 
                               uint8_t out_left[8], uint8_t out_right[8], 
                               const uint8_t *message, const uint32_t mlen);

void darksonic_384_forkskinny(const uint8_t key[16], const uint8_t nonce[16],
                              uint8_t out_left[16], uint8_t out_right[16], 
                              const uint8_t *message, const uint32_t mlen);
void darksonic_256_forkskinny(const uint8_t key[16], const uint8_t nonce[16],
                              uint8_t out_left[16], uint8_t out_right[16], 
                              const uint8_t *message, const uint32_t mlen);
void darksonic_192_forkskinny(const uint8_t key[16], const uint8_t nonce[8],
                              uint8_t out_left[8], uint8_t out_right[8], 
                              const uint8_t *message, const uint32_t mlen);

void babysonic_384_forkskinny(const uint8_t key[16], 
                              uint8_t out_left[16], uint8_t out_right[16], 
                              const uint8_t *message, const uint32_t mlen);
void babysonic_256_forkskinny(const uint8_t key[16], 
                              uint8_t out_left[16], uint8_t out_right[16], 
                              const uint8_t *message, const uint32_t mlen);

#endif /* SONICS_REF */