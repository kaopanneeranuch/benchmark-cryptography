#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "butterknife.h"
#include "sonics_ref.h"
#include "internal-forkskinny.h"

static void arrXOR(uint8_t *out, const uint8_t *right, uint16_t len){
    for(uint8_t i = 0; i<len; ++i){
        out[i] ^= right[i];
    }
}

/* Double Function in GF(2^128) */
static void arrDOUBLE_128(uint8_t out[16]){
    uint8_t tmp;
    
    tmp = (out[15] >> 7) & 1;
    for (uint8_t i = 0;  i < 15;  ++i){
        out[i] = (out[i] << 1) | ((out[i+1] >> 7) & 1);
    }
    out[15] = out[15] << 1;
    out[0] ^= 0x87 * tmp;
}

/* Double Function in GF(2^64) */
static void arrDOUBLE_64(uint8_t out[8]){
    uint8_t tmp;
    
    tmp = (out[7] >> 7) & 1;
    for (uint8_t i = 0;  i < 7;  ++i){
        out[i] = (out[i] << 1) | ((out[i+1] >> 7) & 1);
    }
    out[7] = out[7] << 1;
    out[0] ^= 0x1b * tmp;
}

static void supersonic_384_round(Sonics_384_struct_t *Sonic, SonicChains *Chains, uint8_t buffer[SONICS_384_K_SIZE + SONICS_384_T_SIZE + 1], uint16_t Nr){
    /* Round function */
    arrXOR(Chains->kt, Sonic->P + SONICS_384_N_SIZE, SONICS_384_K_SIZE); //k-Chain
    arrXOR(Sonic->P, Sonic->mask, SONICS_384_N_SIZE); //input-block
    arrXOR(Sonic->P + SONICS_384_N_SIZE, Sonic->K_prime, SONICS_384_K_SIZE); //key-block
    /* Set counter into 12 bit but keeps last 4 empty*/
    Sonic->P[SONICS_384_P_SIZE - 1] = (uint8_t)((Nr+1)&0xff);        //tweak-block
    Sonic->P[SONICS_384_P_SIZE    ] = (uint8_t)(((Nr+1)&0x0f00)>>4);
    forkskinny_128_384_init_tks_part(Sonic->fs_tks1, Sonic->P + SONICS_384_N_SIZE                      , FORKSKINNY_128_384_ROUNDS_BEFORE + FORKSKINNY_128_384_ROUNDS_AFTER, 0); //reduced rounds
    forkskinny_128_384_init_tks_part(Sonic->fs_tks2, Sonic->P + SONICS_384_N_SIZE + SONICS_384_K_SIZE  , FORKSKINNY_128_384_ROUNDS_BEFORE + FORKSKINNY_128_384_ROUNDS_AFTER, 1); //reduced rounds
    forkskinny_128_384_init_tks_part(Sonic->fs_tks3, Sonic->P + SONICS_384_N_SIZE + SONICS_384_K_SIZE*2, FORKSKINNY_128_384_ROUNDS_BEFORE + FORKSKINNY_128_384_ROUNDS_AFTER, 2); //reduced rounds
    forkskinny_128_384_encrypt_with_tks(Sonic->fs_tks1, Sonic->fs_tks2, Sonic->fs_tks3, 0, buffer, Sonic->P); // in this forkskinny implementation the right output is the first branch

    arrXOR(Chains->m,  buffer, SONICS_384_N_SIZE); //m-Chain
    arrDOUBLE_128(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_384_N_SIZE + SONICS_384_K_SIZE, SONICS_384_T_SIZE); //t-Chain
    arrXOR(Chains->kt + SONICS_384_K_SIZE, buffer, SONICS_384_T_SIZE); 
}

static void supersonic_256_round(Sonics_256_struct_t *Sonic, SonicChains *Chains, uint8_t buffer[SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1], uint16_t Nr){
    /* Round function */
    arrXOR(Chains->kt, Sonic->P + SONICS_256_N_SIZE, SONICS_256_K_SIZE); //k-Chain
    arrXOR(Sonic->P, Sonic->mask, SONICS_256_N_SIZE); //input-block
    arrXOR(Sonic->P + SONICS_256_N_SIZE, Sonic->K_prime, SONICS_256_K_SIZE); //key-block
    /* Set counter into 12 bit but keeps last 4 empty*/
    Sonic->P[SONICS_256_P_SIZE - 1] = (uint8_t)((Nr+1)&0xff);        //tweak-block
    Sonic->P[SONICS_256_P_SIZE    ] = (uint8_t)(((Nr+1)&0x0f00)>>4);
    forkskinny_128_256_init_tks_part(Sonic->fs_tks1, Sonic->P + SONICS_256_N_SIZE                      , FORKSKINNY_128_256_ROUNDS_BEFORE + FORKSKINNY_128_256_ROUNDS_AFTER, 0); //reduced rounds
    forkskinny_128_256_init_tks_part(Sonic->fs_tks2, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE  , FORKSKINNY_128_256_ROUNDS_BEFORE + FORKSKINNY_128_256_ROUNDS_AFTER, 1); //reduced rounds
    forkskinny_128_256_encrypt_with_tks(Sonic->fs_tks1, Sonic->fs_tks2, 0, buffer, Sonic->P); // in this forkskinny implementation the right output is the first branch

    arrXOR(Chains->m,  buffer, SONICS_256_N_SIZE); //m-Chain
    arrDOUBLE_128(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, SONICS_256_T_SIZE); //t-Chain
    arrXOR(Chains->kt + SONICS_256_K_SIZE, buffer, SONICS_256_T_SIZE); 
}

static void supersonic_192_round(Sonics_192_struct_t *Sonic, SonicChains *Chains, uint8_t buffer[SONICS_192_K_SIZE + SONICS_192_T_SIZE + 1], uint16_t Nr){
    /* Round function */
    arrXOR(Chains->kt, Sonic->P + SONICS_192_N_SIZE, SONICS_192_K_SIZE); //k-Chain
    arrXOR(Sonic->P, Sonic->mask, SONICS_192_N_SIZE); //input-block
    arrXOR(Sonic->P + SONICS_192_N_SIZE, Sonic->K_prime, SONICS_192_K_SIZE); //key-block
    /* Set counter into 12 bit but keeps last 4 empty*/
    Sonic->P[SONICS_192_P_SIZE - 1] = (uint8_t)((Nr+1)&0xff);        //tweak-block
    Sonic->P[SONICS_192_P_SIZE    ] = (uint8_t)(((Nr+1)&0x0f00)>>4);
    forkskinny_64_192_init_tks_keypart(Sonic->fs_tks1, Sonic->P + SONICS_192_N_SIZE, FORKSKINNY_64_192_ROUNDS_BEFORE + FORKSKINNY_64_192_ROUNDS_AFTER); //reduced rounds
    forkskinny_64_192_init_tks_tweakpart(Sonic->fs_tks2, Sonic->P + SONICS_192_N_SIZE + SONICS_192_K_SIZE  , FORKSKINNY_64_192_ROUNDS_BEFORE + FORKSKINNY_64_192_ROUNDS_AFTER); //reduced rounds
    forkskinny_64_192_encrypt_with_tks(Sonic->fs_tks1, Sonic->fs_tks2, 0, buffer, Sonic->P); // in this forkskinny implementation the right output is the first branch

    arrXOR(Chains->m,  buffer, SONICS_192_N_SIZE); //m-Chain
    arrDOUBLE_64(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_192_N_SIZE + SONICS_192_K_SIZE, SONICS_192_T_SIZE); //t-Chain
    arrXOR(Chains->kt + SONICS_192_K_SIZE, buffer, SONICS_192_T_SIZE); 
}

void supersonic_384_forkskinny(const uint8_t key[16], 
                               uint8_t out_left[16], uint8_t out_right[16], 
                               const uint8_t *message, const uint32_t mlen){
    uint8_t res;
    uint16_t i, numP;
    uint8_t K_prime[SONICS_384_K_SIZE], mask[SONICS_384_N_SIZE], buffer[SONICS_384_K_SIZE + SONICS_384_T_SIZE+1];
    forkskinny_128_384_tweakey_schedule_t tks1, tks2, tks3;
    SonicChains Chains;
    Sonics_384_struct_t Sonic;

    res = mlen%(SONICS_384_P_SIZE-1);
    numP = (uint16_t)(mlen/(SONICS_384_P_SIZE-1)) - 1 + (res>0)*1;

    Sonic.fs_tks1 = &tks1;
    Sonic.fs_tks2 = &tks2;
    Sonic.fs_tks3 = &tks3;
    Sonic.K_prime = K_prime;
    Sonic.mask = mask;
    memset(Sonic.P, 0, SONICS_384_P_SIZE + 1);
    memset(Chains.m, 0, SONICS_384_N_SIZE);
    memset(Chains.kt, 0, SONICS_384_K_SIZE + SONICS_384_T_SIZE + 1);
    memset(buffer, 0, SONICS_384_K_SIZE + SONICS_384_T_SIZE + 1);

    // /* Key expansion forkcipher call to generate K' and Mask: FC(K, 0^t, 0^m) */
    forkskinny_128_384_init_tks_part(Sonic.fs_tks1, key       , FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER, 0);
    forkskinny_128_384_init_tks_part(Sonic.fs_tks2, Sonic.P, FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER, 1);
    forkskinny_128_384_init_tks_part(Sonic.fs_tks3, Sonic.P, FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER, 2);
    forkskinny_128_384_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, Sonic.fs_tks3, Sonic.K_prime, Sonic.mask, Sonic.P); 

    for(i=0; i<numP; ++i){            
        /** 
         * Sonic.P order: 
         * M_3i   = 'Input'
         * M_3i+1 = 'Key'
         * M_3i+2 = 'Tweak'
         **/
        memcpy(Sonic.P, message + (SONICS_384_P_SIZE-1)*i, (SONICS_384_P_SIZE-1));
        supersonic_384_round(&Sonic, &Chains, buffer, i);
    }
    /* Padding */
    memset(Sonic.P, 0, SONICS_384_P_SIZE+1);
    Sonic.P[res] = SONICS_END_OF_MESSAGE;
    memcpy(Sonic.P, message + numP*(SONICS_384_P_SIZE-1), (SONICS_384_P_SIZE-1)*(res==0) + res);
    supersonic_384_round(&Sonic, &Chains, buffer, numP);

    /* Last Round */
    Chains.kt[SONICS_384_K_SIZE + SONICS_384_T_SIZE] = 0b01 + (0b10 * (res>0));
    arrXOR(Chains.kt, Sonic.K_prime, SONICS_384_K_SIZE);
    arrXOR(Chains.m,  Sonic.mask, SONICS_384_N_SIZE);
    forkskinny_128_384_init_tks_part(Sonic.fs_tks1, Chains.kt                      , FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER, 0);
    forkskinny_128_384_init_tks_part(Sonic.fs_tks2, Chains.kt + SONICS_384_K_SIZE  , FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER, 1);
    forkskinny_128_384_init_tks_part(Sonic.fs_tks3, Chains.kt + SONICS_384_K_SIZE*2, FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER, 2);
    forkskinny_128_384_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, Sonic.fs_tks3, out_left, out_right, Chains.m);
}

void supersonic_256_forkskinny(const uint8_t key[16], 
                               uint8_t out_left[16], uint8_t out_right[16], 
                               const uint8_t *message, const uint32_t mlen){
    uint8_t res;
    uint16_t i, numP;
    uint8_t K_prime[SONICS_256_K_SIZE], mask[SONICS_256_N_SIZE], buffer[SONICS_256_K_SIZE + SONICS_256_T_SIZE+1];
    forkskinny_128_256_tweakey_schedule_t tks1, tks2;
    SonicChains Chains;
    Sonics_256_struct_t Sonic;

    res = mlen%(SONICS_256_P_SIZE-1);
    numP = (uint16_t)(mlen/(SONICS_256_P_SIZE-1)) - 1 + (res>0)*1;

    Sonic.fs_tks1 = &tks1;
    Sonic.fs_tks2 = &tks2;
    Sonic.K_prime = K_prime;
    Sonic.mask = mask;
    memset(Sonic.P, 0, SONICS_256_P_SIZE + 1);
    memset(Chains.m, 0, SONICS_256_N_SIZE);
    memset(Chains.kt, 0, SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1);
    memset(buffer, 0, SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1);

    // /* Key expansion forkcipher call to generate K' and Mask: FC(K, 0^t, 0^m) */
    forkskinny_128_256_init_tks_part(Sonic.fs_tks1, key    , FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER, 0);
    forkskinny_128_256_init_tks_part(Sonic.fs_tks2, Sonic.P, FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER, 1);
    forkskinny_128_256_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, Sonic.K_prime, Sonic.mask, Sonic.P); 

    for(i=0; i<numP; ++i){            
        /** 
         * Sonic.P order: 
         * M_3i   = 'Input'
         * M_3i+1 = 'Key'
         * M_3i+2 = 'Tweak'
         **/
        memcpy(Sonic.P, message + (SONICS_256_P_SIZE-1)*i, (SONICS_256_P_SIZE-1));
        supersonic_256_round(&Sonic, &Chains, buffer, i);
    }
    /* Padding */
    memset(Sonic.P, 0, SONICS_256_P_SIZE+1);
    Sonic.P[res] = SONICS_END_OF_MESSAGE;
    memcpy(Sonic.P, message + numP*(SONICS_256_P_SIZE-1), (SONICS_256_P_SIZE-1)*(res==0) + res);
    supersonic_256_round(&Sonic, &Chains, buffer, numP);

    /* Last Round */
    Chains.kt[SONICS_256_K_SIZE + SONICS_256_T_SIZE] = 0b01 + (0b10 * (res>0));
    arrXOR(Chains.kt, Sonic.K_prime, SONICS_256_K_SIZE);
    arrXOR(Chains.m,  Sonic.mask, SONICS_256_N_SIZE);
    forkskinny_128_256_init_tks_part(Sonic.fs_tks1, Chains.kt                      , FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER, 0);
    forkskinny_128_256_init_tks_part(Sonic.fs_tks2, Chains.kt + SONICS_256_K_SIZE  , FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER, 1);
    forkskinny_128_256_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, out_left, out_right, Chains.m);
}

void supersonic_192_forkskinny(const uint8_t key[16], 
                               uint8_t out_left[8], uint8_t out_right[8], 
                               const uint8_t *message, const uint32_t mlen){
    uint8_t res;
    uint16_t i, numP;
    uint8_t K_prime[SONICS_192_K_SIZE], mask[SONICS_192_N_SIZE], buffer[SONICS_192_K_SIZE + SONICS_192_T_SIZE+1];
    forkskinny_64_192_tweakey_schedule_t tks1, tks2;
    SonicChains Chains;
    Sonics_192_struct_t Sonic;

    res = mlen%(SONICS_192_P_SIZE-1);
    numP = (uint16_t)(mlen/(SONICS_192_P_SIZE-1)) - 1 + (res>0)*1;

    Sonic.fs_tks1 = &tks1;
    Sonic.fs_tks2 = &tks2;
    Sonic.K_prime = K_prime;
    Sonic.mask = mask;
    memset(Sonic.P, 0, SONICS_192_P_SIZE + 1);
    memset(Chains.m, 0, SONICS_192_N_SIZE);
    memset(Chains.kt, 0, SONICS_192_K_SIZE + SONICS_192_T_SIZE + 1);
    memset(buffer, 0, SONICS_192_K_SIZE + SONICS_192_T_SIZE + 1);

    // /* Key expansion forkcipher call to generate K' and Mask: FC(K, 0^t, 0^m) */
    forkskinny_64_192_init_tks_keypart(Sonic.fs_tks1, key, FORKSKINNY_64_192_ROUNDS_BEFORE + 2*FORKSKINNY_64_192_ROUNDS_AFTER);
    forkskinny_64_192_init_tks_tweakpart(Sonic.fs_tks2, Sonic.P, FORKSKINNY_64_192_ROUNDS_BEFORE + 2*FORKSKINNY_64_192_ROUNDS_AFTER);
    forkskinny_64_192_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, Sonic.K_prime, Sonic.K_prime + SONICS_192_K_SIZE/2, Sonic.P); 
    Sonic.P[SONICS_192_N_SIZE -1] = 1;
    forkskinny_64_192_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, 0, Sonic.mask, Sonic.P);

    for(i=0; i<numP; ++i){            
        /** 
         * Sonic.P order: 
         * M_3i   = 'Input'
         * M_3i+1 = 'Key'
         * M_3i+2 = 'Tweak'
         **/
        memcpy(Sonic.P, message + (SONICS_192_P_SIZE-1)*i, (SONICS_192_P_SIZE-1));
        supersonic_192_round(&Sonic, &Chains, buffer, i);
    }
    /* Padding */
    memset(Sonic.P, 0, SONICS_192_P_SIZE+1);
    Sonic.P[res] = SONICS_END_OF_MESSAGE;
    memcpy(Sonic.P, message + numP*(SONICS_192_P_SIZE-1), (SONICS_192_P_SIZE-1)*(res==0) + res);
    supersonic_192_round(&Sonic, &Chains, buffer, numP);

    /* Last Round */
    Chains.kt[SONICS_192_K_SIZE + SONICS_192_T_SIZE] = 0b01 + (0b10 * (res>0));
    arrXOR(Chains.kt, Sonic.K_prime, SONICS_192_K_SIZE);
    arrXOR(Chains.m,  Sonic.mask, SONICS_192_N_SIZE);
    forkskinny_64_192_init_tks_keypart(Sonic.fs_tks1, Chains.kt, FORKSKINNY_64_192_ROUNDS_BEFORE + 2*FORKSKINNY_64_192_ROUNDS_AFTER);
    forkskinny_64_192_init_tks_tweakpart(Sonic.fs_tks2, Chains.kt + SONICS_192_K_SIZE, FORKSKINNY_64_192_ROUNDS_BEFORE + 2*FORKSKINNY_64_192_ROUNDS_AFTER);
    forkskinny_64_192_encrypt_with_tks(Sonic.fs_tks1, Sonic.fs_tks2, out_left, out_right, Chains.m);
}
