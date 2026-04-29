#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "include/butterknife.h"
#include "include/sonics_ref.h"
#include "deoxysbc256_opt.h"

/* Call counters */
static uint32_t cnt_1leg;
static uint32_t cnt_2leg;

void supersonic_bk_deoxys_opt_reset_counters(void)
{
    cnt_1leg = cnt_2leg = 0;
}

void supersonic_bk_deoxys_opt_get_counters(uint32_t *oneleg, uint32_t *twoleg)
{
    *oneleg = cnt_1leg;
    *twoleg = cnt_2leg;
}

static void arrXOR(uint8_t *out, const uint8_t *right, uint16_t len)
{
    for (uint8_t i = 0; i < len; ++i) {
        out[i] ^= right[i];
    }
}

/* Double Function in GF(2^128) */
static void arrDOUBLE_128(uint8_t out[16])
{
    uint8_t tmp;

    tmp = (out[15] >> 7) & 1;
    for (uint8_t i = 0; i < 15; ++i) {
        out[i] = (out[i] << 1) | ((out[i + 1] >> 7) & 1);
    }
    out[15] = out[15] << 1;
    out[0] ^= 0x87 * tmp;
}

/* ------------------------------------------------------------------------- */
/* Deoxys-I-128 one-leg helper: Deoxys-BC-256, 2 TK words, 14 rounds       */
/* ------------------------------------------------------------------------- */

static void deoxysBC_256_encrypt_1leg(const uint8_t tk[32],
                                      uint8_t out[16],
                                      const uint8_t in[16])
{
    deoxysbc256_encrypt_full(tk, in, out);
    cnt_1leg++;
}

/* ------------------------------------------------------------------------- */
/* Shared per-round logic                                                    */
/* ------------------------------------------------------------------------- */

static void supersonic_256_round_core(Sonics_256_struct_t *Sonic,
                                      SonicChains *Chains,
                                      uint8_t buffer[SONICS_256_N_SIZE],
                                      uint16_t Nr)
{
    uint8_t tk[32];

    arrXOR(Chains->kt, Sonic->P + SONICS_256_N_SIZE, SONICS_256_K_SIZE);
    arrXOR(Sonic->P, Sonic->mask, SONICS_256_N_SIZE);
    arrXOR(Sonic->P + SONICS_256_N_SIZE, Sonic->K_prime, SONICS_256_K_SIZE);

    Sonic->P[SONICS_256_P_SIZE - 1] = (uint8_t)((Nr + 1) & 0xff);
    Sonic->P[SONICS_256_P_SIZE]     = (uint8_t)(((Nr + 1) & 0x0f00) >> 4);

    memcpy(tk,      Sonic->P + SONICS_256_N_SIZE,                     16);
    memcpy(tk + 16, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, 16);

    deoxysBC_256_encrypt_1leg(tk, buffer, Sonic->P);

    arrXOR(Chains->m, buffer, SONICS_256_N_SIZE);
    arrDOUBLE_128(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, SONICS_256_T_SIZE);
    arrXOR(Chains->kt + SONICS_256_K_SIZE, buffer, SONICS_256_T_SIZE);
}

/* ------------------------------------------------------------------------- */
/* Shared driver                                                             */
/* ------------------------------------------------------------------------- */

static void supersonic_256_butterknife_core(
    const uint8_t key[16],
    uint8_t out_left[16],
    uint8_t out_right[16],
    const uint8_t *message,
    const uint32_t mlen)
{
    uint8_t res;
    uint16_t i, numP;
    uint8_t Kmask[SONICS_256_K_SIZE + SONICS_256_N_SIZE];
    uint8_t buffer[32];   /* final Butterknife call returns 2 legs = 32 bytes */
    static uint32_t rtk[4 * (BUTTERKNIFE_ROUNDS + 1)];
    SonicChains Chains;
    Sonics_256_struct_t Sonic;

    res  = mlen % (SONICS_256_P_SIZE - 1);
    numP = (uint16_t)(mlen / (SONICS_256_P_SIZE - 1)) - 1 + (res > 0) * 1;

    Sonic.bk_rtk  = rtk;
    Sonic.K_prime = Kmask;
    Sonic.mask    = Kmask + SONICS_256_K_SIZE;

    memset(Sonic.P, 0, SONICS_256_P_SIZE + 1);
    memset(Chains.m, 0, SONICS_256_N_SIZE);
    memset(Chains.kt, 0, SONICS_256_K_SIZE + SONICS_256_T_SIZE + 1);
    memset(buffer, 0, sizeof(buffer));

    /*
     * 2-leg precompute stays Butterknife:
     * FC(K, 0^t, 0^m) -> K' || mask
     */
    memcpy(Sonic.P, key, SONICS_256_K_SIZE);
    butterknife_256_precompute_rtk(Sonic.P, Sonic.bk_rtk, 2);
    butterknife_256_encrypt_w_rtk(Sonic.bk_rtk, Kmask, Sonic.P + SONICS_256_K_SIZE, 2);
    cnt_2leg++;

    for (i = 0; i < numP; ++i) {
        /*
         * Sonic.P order:
         * M_3i   = input
         * M_3i+1 = key-part
         * M_3i+2 = tweak-part
         */
        memcpy(Sonic.P, message + (SONICS_256_P_SIZE - 1) * i, (SONICS_256_P_SIZE - 1));

        supersonic_256_round_core(&Sonic, &Chains, buffer, i);
    }

    /* Padding */
    memset(Sonic.P, 0, SONICS_256_P_SIZE + 1);
    Sonic.P[res] = SONICS_END_OF_MESSAGE;
    memcpy(Sonic.P,
           message + numP * (SONICS_256_P_SIZE - 1),
           (SONICS_256_P_SIZE - 1) * (res == 0) + res);

    supersonic_256_round_core(&Sonic, &Chains, buffer, numP);

    /* Final 2-leg call stays Butterknife */
    Chains.kt[SONICS_256_K_SIZE + SONICS_256_T_SIZE] = 0b01 + (0b10 * (res > 0));
    arrXOR(Chains.kt, Sonic.K_prime, SONICS_256_K_SIZE);
    arrXOR(Chains.m,  Sonic.mask,    SONICS_256_N_SIZE);

    butterknife_256_precompute_rtk(Chains.kt, Sonic.bk_rtk, 2);
    butterknife_256_encrypt_w_rtk(Sonic.bk_rtk, buffer, Chains.m, 2);
    cnt_2leg++;

    memcpy(out_left,  buffer,     SONICS_256_N_SIZE);
    memcpy(out_right, buffer + 16, SONICS_256_N_SIZE);
}

/* ------------------------------------------------------------------------- */
/* Public entry points                                                       */
/* ------------------------------------------------------------------------- */

void supersonic_256_butterknife_deoxys_opt(const uint8_t key[16],
                                           uint8_t out_left[16],
                                           uint8_t out_right[16],
                                           const uint8_t *message,
                                           const uint32_t mlen)
{
    supersonic_256_butterknife_core(key, out_left, out_right, message, mlen);
}