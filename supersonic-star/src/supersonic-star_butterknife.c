#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "include/butterknife.h"
#include "include/sonics_ref.h"
#include "skinny.h"

/*
 * Butterknife / Deoxys-BC hybrid for SuperSonic-256.
 *
 * Both versions keep:
 *   - 2-leg precompute    -> Butterknife
 *   - 2-leg finalization  -> Butterknife
 *
 * They differ only in the 1-leg absorb round:
 *
 *   exact:
 *     full-round Deoxys-BC-256 style block call
 *
 *   star:
 *     reduced-round Deoxys-BC-256 style block call
 *
 */

#define SUPERSONIC_STAR_BK256_ROUNDS 32u

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
/* Deoxys-BC-256 style one-leg helpers                                       */
/* ------------------------------------------------------------------------- */

/*
 * EXACT helper:
 * same low-level pattern as deoxys.c:
 *   TK1 = key part
 *   TK2 = tweak part
 *   full-round SKINNY-128-256 with tweakey schedules
 */
static void deoxysBC_256_encrypt_exact(const uint8_t tk[32],
                                       uint8_t out[16],
                                       const uint8_t in[16])
{
    static skinny_128_256_tweakey_schedule_t tks1, tks2;

    skinny_128_256_init_tk1(&tks1, tk,      SKINNY_128_256_ROUNDS);
    skinny_128_256_init_tk2(&tks2, tk + 16, SKINNY_128_256_ROUNDS);
    skinny_128_256_encrypt_with_tks(&tks1, &tks2, out, in);
}

/*
 * STAR helper:
 * same Deoxys-BC-256 style structure, but reduced rounds for speed testing.
 */
static void deoxysBC_256_encrypt_star(const uint8_t tk[32],
                                      uint8_t out[16],
                                      const uint8_t in[16])
{
    static skinny_128_256_tweakey_schedule_t tks1, tks2;
    skinny_128_256_state_t state;

    skinny_128_256_init_tk1(&tks1, tk,      SUPERSONIC_STAR_BK256_ROUNDS);
    skinny_128_256_init_tk2(&tks2, tk + 16, SUPERSONIC_STAR_BK256_ROUNDS);

    state.S[0] = le_load_word32(in);
    state.S[1] = le_load_word32(in + 4);
    state.S[2] = le_load_word32(in + 8);
    state.S[3] = le_load_word32(in + 12);

    skinny_128_256_rounds(&state, &tks1, &tks2, 0, SUPERSONIC_STAR_BK256_ROUNDS);

    le_store_word32(out,      state.S[0]);
    le_store_word32(out + 4,  state.S[1]);
    le_store_word32(out + 8,  state.S[2]);
    le_store_word32(out + 12, state.S[3]);
}

/* ------------------------------------------------------------------------- */
/* Shared per-round logic                                                    */
/* ------------------------------------------------------------------------- */

static void supersonic_256_round_exact(Sonics_256_struct_t *Sonic,
                                       SonicChains *Chains,
                                       uint8_t buffer[SONICS_256_N_SIZE],
                                       uint16_t Nr)
{
    uint8_t tk[32];

    /* Round function */
    arrXOR(Chains->kt, Sonic->P + SONICS_256_N_SIZE, SONICS_256_K_SIZE);             /* k-chain */
    arrXOR(Sonic->P, Sonic->mask, SONICS_256_N_SIZE);                                 /* input-block */
    arrXOR(Sonic->P + SONICS_256_N_SIZE, Sonic->K_prime, SONICS_256_K_SIZE);          /* key-block */

    /* Set counter into 12 bits but keep last 4 empty */
    Sonic->P[SONICS_256_P_SIZE - 1] = (uint8_t)((Nr + 1) & 0xff);
    Sonic->P[SONICS_256_P_SIZE]     = (uint8_t)(((Nr + 1) & 0x0f00) >> 4);

    /*
     * Deoxys-BC-256 tweakey = KEY || TWEAK
     */
    memcpy(tk,      Sonic->P + SONICS_256_N_SIZE,                     16);
    memcpy(tk + 16, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, 16);

    deoxysBC_256_encrypt_exact(tk, buffer, Sonic->P);

    arrXOR(Chains->m, buffer, SONICS_256_N_SIZE);                                    /* m-chain */
    arrDOUBLE_128(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, SONICS_256_T_SIZE); /* t-chain */
    arrXOR(Chains->kt + SONICS_256_K_SIZE, buffer, SONICS_256_T_SIZE);
}

static void supersonic_256_round_star(Sonics_256_struct_t *Sonic,
                                      SonicChains *Chains,
                                      uint8_t buffer[SONICS_256_N_SIZE],
                                      uint16_t Nr)
{
    uint8_t tk[32];

    /* Round function */
    arrXOR(Chains->kt, Sonic->P + SONICS_256_N_SIZE, SONICS_256_K_SIZE);             /* k-chain */
    arrXOR(Sonic->P, Sonic->mask, SONICS_256_N_SIZE);                                 /* input-block */
    arrXOR(Sonic->P + SONICS_256_N_SIZE, Sonic->K_prime, SONICS_256_K_SIZE);          /* key-block */

    /* Set counter into 12 bits but keep last 4 empty */
    Sonic->P[SONICS_256_P_SIZE - 1] = (uint8_t)((Nr + 1) & 0xff);
    Sonic->P[SONICS_256_P_SIZE]     = (uint8_t)(((Nr + 1) & 0x0f00) >> 4);

    /*
     * Deoxys-BC-256 tweakey = KEY || TWEAK
     */
    memcpy(tk,      Sonic->P + SONICS_256_N_SIZE,                     16);
    memcpy(tk + 16, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, 16);

    deoxysBC_256_encrypt_star(tk, buffer, Sonic->P);

    arrXOR(Chains->m, buffer, SONICS_256_N_SIZE);                                    /* m-chain */
    arrDOUBLE_128(Chains->m);
    arrXOR(buffer, Sonic->P + SONICS_256_N_SIZE + SONICS_256_K_SIZE, SONICS_256_T_SIZE); /* t-chain */
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
    const uint32_t mlen,
    int use_star)
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

    for (i = 0; i < numP; ++i) {
        /*
         * Sonic.P order:
         * M_3i   = input
         * M_3i+1 = key-part
         * M_3i+2 = tweak-part
         */
        memcpy(Sonic.P, message + (SONICS_256_P_SIZE - 1) * i, (SONICS_256_P_SIZE - 1));

        if (use_star) {
            supersonic_256_round_star(&Sonic, &Chains, buffer, i);
        } else {
            supersonic_256_round_exact(&Sonic, &Chains, buffer, i);
        }
    }

    /* Padding */
    memset(Sonic.P, 0, SONICS_256_P_SIZE + 1);
    Sonic.P[res] = SONICS_END_OF_MESSAGE;
    memcpy(Sonic.P,
           message + numP * (SONICS_256_P_SIZE - 1),
           (SONICS_256_P_SIZE - 1) * (res == 0) + res);

    if (use_star) {
        supersonic_256_round_star(&Sonic, &Chains, buffer, numP);
    } else {
        supersonic_256_round_exact(&Sonic, &Chains, buffer, numP);
    }

    /* Final 2-leg call stays Butterknife */
    Chains.kt[SONICS_256_K_SIZE + SONICS_256_T_SIZE] = 0b01 + (0b10 * (res > 0));
    arrXOR(Chains.kt, Sonic.K_prime, SONICS_256_K_SIZE);
    arrXOR(Chains.m,  Sonic.mask,    SONICS_256_N_SIZE);

    butterknife_256_precompute_rtk(Chains.kt, Sonic.bk_rtk, 2);
    butterknife_256_encrypt_w_rtk(Sonic.bk_rtk, buffer, Chains.m, 2);

    memcpy(out_left,  buffer,     SONICS_256_N_SIZE);
    memcpy(out_right, buffer + 16, SONICS_256_N_SIZE);
}

/* ------------------------------------------------------------------------- */
/* Public entry points                                                       */
/* ------------------------------------------------------------------------- */

void supersonic_256_butterknife_deoxys_exact(const uint8_t key[16],
                                             uint8_t out_left[16],
                                             uint8_t out_right[16],
                                             const uint8_t *message,
                                             const uint32_t mlen)
{
    supersonic_256_butterknife_core(key, out_left, out_right, message, mlen, 0);
}

void supersonic_256_butterknife_star(const uint8_t key[16],
                                     uint8_t out_left[16],
                                     uint8_t out_right[16],
                                     const uint8_t *message,
                                     const uint32_t mlen)
{
    supersonic_256_butterknife_core(key, out_left, out_right, message, mlen, 1);
}