#include <stdint.h>
#include <string.h>
#include "../include/butterknife.h"

// The lookup-table is marked volatile to guarantee constant code execution time
// The numbers below can be computed dynamically trading ROM for RAM
volatile uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     d     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint32_t state[4], const uint32_t* rtk, const uint8_t branch)
{
  state[0] ^= rtk[0];
  state[1] ^= rtk[1];
  state[2] ^= rtk[2] ^ (uint32_t)((branch << 24) | (branch << 16) | (branch << 8) | branch);
  state[3] ^= rtk[3];
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(uint32_t state[4])
{
  uint8_t i;
  for (i = 0; i < 4; ++i){
    state[i] =    GETSBOXVAL((uint8_t)state[i]) 
                | GETSBOXVAL((uint8_t)(state[i]>> 8))<< 8 
                | GETSBOXVAL((uint8_t)(state[i]>>16))<<16 
                | GETSBOXVAL((uint8_t)(state[i]>>24))<<24;
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(uint32_t state[4])
{
  uint32_t buf[4];
  memcpy(buf, state, 4*(sizeof(uint32_t)));

  state[0] = (buf[0] & 0xff000000) | (buf[1] & 0xff0000) | (buf[2] & 0xff00) | (buf[3] & 0xff);
  state[1] = (buf[1] & 0xff000000) | (buf[2] & 0xff0000) | (buf[3] & 0xff00) | (buf[0] & 0xff);
  state[2] = (buf[2] & 0xff000000) | (buf[3] & 0xff0000) | (buf[0] & 0xff00) | (buf[1] & 0xff);
  state[3] = (buf[3] & 0xff000000) | (buf[0] & 0xff0000) | (buf[1] & 0xff00) | (buf[2] & 0xff);
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(uint32_t state[4])
{
  uint8_t i;
  uint8_t Tmp, Tm, t;

  for (i = 0; i < 4; ++i){  
    t   = (uint8_t)(state[i]>>24);
    Tmp = (uint8_t)((state[i]>>24) ^ (state[i]>>16) ^ (state[i]>>8) ^ state[i]) ;
    Tm  = (uint8_t)((state[i]>>24) ^ (state[i]>>16));
    Tm  = XTIME(Tm);
    state[i] ^= (uint32_t)((Tm ^ Tmp)<<24);

    Tm  = (uint8_t)((state[i]>>16) ^ (state[i]>>8));
    Tm  = XTIME(Tm);
    state[i] ^= (uint32_t)((Tm ^ Tmp)<<16) ;

    Tm  = (uint8_t)((state[i]>>8) ^ state[i]);
    Tm  = XTIME(Tm);
    state[i] ^= (uint32_t)((Tm ^ Tmp)<<8) ;

    Tm  = (uint8_t)(state[i] ^ t);
    Tm  = XTIME(Tm);
    state[i] ^= (uint32_t)(Tm ^ Tmp);
  }
}

void deoxysBC_256_encrypt_w_rtk(const uint32_t rtk[4*15], uint8_t output[16], const uint8_t message[16]){
  uint8_t round = 0;
  uint32_t state[4];

  state[0] = GETU32(message     );
  state[1] = GETU32(message +  4);
  state[2] = GETU32(message +  8);
  state[3] = GETU32(message + 12);

  for (round = 0; round < 14; ++round)
  {
    AddRoundKey(state, rtk + 4*round, 0);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
  }
  AddRoundKey(state, rtk + 14*4, 0);
  
  /* Put the state into the ciphertext */
  PUTU32(output     , state[0]);
  PUTU32(output +  4, state[1]);
  PUTU32(output +  8, state[2]);
  PUTU32(output + 12, state[3]);
}

void deoxysBC_256_encrypt(const uint8_t tweakey[32], uint8_t output[16], const uint8_t message[16]){
  uint32_t rtk[4*15];

  butterknife_256_precompute_rtk(tweakey, rtk, 0);
  deoxysBC_256_encrypt_w_rtk(rtk, output, message);
}

void butterknife_256_encrypt_w_rtk(const uint32_t rtk[4*16], uint8_t* output, const uint8_t message[16], const uint8_t num_branches){
  uint8_t branch, round;
	uint32_t state[4], forkstate[4];

  forkstate[0] = GETU32(message     );
  forkstate[1] = GETU32(message +  4);
  forkstate[2] = GETU32(message +  8);
  forkstate[3] = GETU32(message + 12);

  for (round = 0; round < BUTTERKNIFE_ROOT_ROUNDS; ++round){
    AddRoundKey(forkstate, rtk + round*4, 0);
    SubBytes(forkstate);
    ShiftRows(forkstate);
    MixColumns(forkstate);
  }

  for (branch = 0; branch < num_branches; ++branch){
    memcpy(state, forkstate, sizeof(state));
    for(round = 0; round < BUTTERKNIFE_BRANCH_ROUNDS; ++round){
      AddRoundKey(state, rtk + (round + BUTTERKNIFE_ROOT_ROUNDS)*4, branch+1);
      SubBytes(state);
      ShiftRows(state);
      MixColumns(state);
    }
    AddRoundKey(state, rtk + BUTTERKNIFE_ROUNDS*4, branch+1);
    XOR_STATES(state, forkstate);

    /* Put the state into the ciphertext */
    PUTU32(output + 16*branch     , state[0]);
    PUTU32(output + 16*branch +  4, state[1]);
    PUTU32(output + 16*branch +  8, state[2]);
    PUTU32(output + 16*branch + 12, state[3]);
  }
}

void butterknife_256_encrypt(const uint8_t tweakey[32], uint8_t* output, const uint8_t message[16], const uint8_t num_branches){
  uint32_t rtk[4*(BUTTERKNIFE_ROUNDS+1)];

  butterknife_256_precompute_rtk(tweakey, rtk, num_branches);
  butterknife_256_encrypt_w_rtk(rtk, output, message, num_branches);
}