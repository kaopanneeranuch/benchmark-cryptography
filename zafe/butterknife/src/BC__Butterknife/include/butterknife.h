#ifndef BK_H
#define BK_H
#include <stdint.h>

#define BUTTERKNIFE_ROOT_ROUNDS 7
#define BUTTERKNIFE_BRANCH_ROUNDS 8
#define BUTTERKNIFE_ROUNDS (BUTTERKNIFE_ROOT_ROUNDS + BUTTERKNIFE_BRANCH_ROUNDS)
#define BUTTERKNIFE_MAX_BRANCHES 8

/* Makros */
#define GETRCON(r) ( ((uint32_t)rcon[r]<<24) ^ ((uint32_t)rcon[r]<<16) ^ ((uint32_t)rcon[r]<<8) ^ ((uint32_t)rcon[r]<<0) )
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }

#define GETSBOXVAL(num) (sbox[(num)])
#define XTIME(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))
#define XOR_STATES(x,y) ({ 				  \
	(x)[0] ^= (y)[0];				      \
	(x)[1] ^= (y)[1];				      \
	(x)[2] ^= (y)[2];				      \
	(x)[3] ^= (y)[3];				      \
})

/* Tweakey Schedule */
void butterknife_256_precompute_rtk(const uint8_t tweakey[32], uint32_t* rtk, const uint8_t num_branch);

/* Encryption */
void deoxysBC_256_encrypt_w_rtk(const uint32_t rtk[4*15], uint8_t output[16], const uint8_t message[16]);
void deoxysBC_256_encrypt(const uint8_t tweakey[32], uint8_t output[16], const uint8_t message[16]);

void butterknife_256_encrypt_w_rtk(const uint32_t rtk[4*16], uint8_t* output, const uint8_t message[16], const uint8_t num_branches);
void butterknife_256_encrypt(const uint8_t tweakey[32], uint8_t* output, const uint8_t message[16], const uint8_t num_branches);

#endif /* BK_H */
 
