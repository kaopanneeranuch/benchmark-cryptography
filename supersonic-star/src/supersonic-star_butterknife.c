#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../include/butterknife.h"
#include "../include/sonics_ref.h"
#include "../forkskinny-opt32/internal-forkskinny.h"

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

static void supersonic_256_round(Sonics_256_struct_t *Sonic, SonicChains *Chains, uint8_t buffer[SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1], uint16_t Nr){
    /* Round function */
    arrXOR(Chains->kt, Sonic->P + SONICS_256_N_SIZE, SONICS_256_K_SIZE); //k-Chain
    arrXOR(Sonic->P, Sonic->mask, SONICS_256_N_SIZE); //input-block
    arrXOR(Sonic->P + SONICS_256_N_SIZE, Sonic->K_prime, SONICS_256_K_SIZE); //key-block
    /* Set counter into 12 bit but keeps last 4 empty*/
    Sonic->P[SONICS_256_P_SIZE - 1] = (uint8_t)((Nr+1)&0xff);        //tweak-block
    Sonic->P[SONICS_256_P_SIZE    ] = (uint8_t)(((Nr+1)&0x0f00)>>4);
    butterknife_256_precompute_rtk(Sonic->P + SONICS_256_N_SIZE, Sonic->bk_rtk, 0);
    deoxysBC_256_encrypt_w_rtk(Sonic->bk_rtk, buffer, Sonic->P);
    
    arrXOR(Chains->m,  buffer, SONICS_256_N_SIZE); //m-Chain
    arrDOUBLE_128(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, SONICS_256_T_SIZE); //t-Chain
    arrXOR(Chains->kt + SONICS_256_K_SIZE, buffer, SONICS_256_T_SIZE); 
}

void supersonic_256_butterknife(const uint8_t key[16], 
                                uint8_t out_left[16], uint8_t out_right[16], 
                                const uint8_t *message, const uint32_t mlen){
    uint8_t res;
    uint16_t i, numP;
    uint8_t Kmask[SONICS_256_K_SIZE + SONICS_256_N_SIZE], buffer[SONICS_256_K_SIZE + SONICS_256_T_SIZE+1];
    uint32_t rtk[4*(BUTTERKNIFE_ROUNDS+1)];
    SonicChains Chains;
    Sonics_256_struct_t Sonic;

    res = mlen%(SONICS_256_P_SIZE-1);
    numP = (uint16_t)(mlen/(SONICS_256_P_SIZE-1)) - 1 + (res>0)*1;

    Sonic.bk_rtk = rtk;
    Sonic.K_prime = Kmask;
    Sonic.mask = Kmask + SONICS_256_K_SIZE;
    memset(Sonic.P, 0, SONICS_256_P_SIZE + 1);
    memset(Chains.m, 0, SONICS_256_N_SIZE);
    memset(Chains.kt, 0, SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1);
    memset(buffer, 0, SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1);

    /* Key expansion forkcipher call to generate K' and Mask: FC(K, 0^t, 0^m) */
    memcpy(Sonic.P, key, SONICS_256_K_SIZE);
    butterknife_256_precompute_rtk(Sonic.P, Sonic.bk_rtk, 2);
    butterknife_256_encrypt_w_rtk(Sonic.bk_rtk, Kmask, Sonic.P + SONICS_256_K_SIZE, 2);

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
    butterknife_256_precompute_rtk(Chains.kt, Sonic.bk_rtk, 2);
    butterknife_256_encrypt_w_rtk(Sonic.bk_rtk, buffer, Chains.m, 2);

    memcpy(out_left, buffer, SONICS_256_N_SIZE);
    memcpy(out_right, buffer + SONICS_256_N_SIZE, SONICS_256_N_SIZE);
}
