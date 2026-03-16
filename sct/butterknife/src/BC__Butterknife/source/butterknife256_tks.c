/*
 * Deoxys=-256-128 Reference C Implementation
 *
 * Copyright 2014:
 *     Jeremy Jean <JJean@ntu.edu.sg>
 *     Ivica Nikolic <INikolic@ntu.edu.sg>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <stdint.h>
#include <string.h>
#include "../include/butterknife.h"

static const uint8_t perm[16] = {1,6,11,12,5,10,15,0,9,14,3,4,13,2,7,8};

static const uint8_t rcon[17] = {
	0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,
	0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,
	0x72
};

/*
** Function G form the specifications
*/
static void G (uint8_t tweakey[], uint8_t alpha) {
  int i;
  if(alpha == 2){
 	  for(i=0; i<16; i++) tweakey[i] = (tweakey[i]<<1) | ((tweakey[i]&0x20)>>5 ^ (tweakey[i]&0x80)>>7);
  }
}

/*
** Function H form the specifications
*/
static void H (uint8_t tweakey[]) {
  int i;
  uint8_t tmp[16];
  for( i = 0; i<16; i++) tmp[perm[i]] = tweakey[i];
  memcpy (tweakey, tmp, 16);
}

/*
 Precomputes the round subtweakeys for the encryption process
 num_branch is the number of branches in the fork
 if num_branch = 0 key schedule for Deoxys-BC (one less round)
 branch-specific additional RC get added in butterknife256 AddRoundKey()
*/
void butterknife_256_precompute_rtk(const uint8_t tweakey[32], uint32_t* rtk, const uint8_t num_branch)
{
  uint8_t r;
  uint8_t tk[2][16];
  uint8_t Nr = BUTTERKNIFE_ROUNDS - 1 + (num_branch>0)*1;
  uint32_t rcon_row1 = 0x01020408;

  memcpy (tk[0], tweakey +  0, 16);
  memcpy (tk[1], tweakey + 16, 16);

  for(r=0; r<= Nr; ++r) {
    /* Produce the round tk */
    rtk[ 4*r + 0] = GETU32( tk[0] +  0) ^ GETU32( tk[1] +  0) ^ rcon_row1 ;
    rtk[ 4*r + 1] = GETU32( tk[0] +  4) ^ GETU32( tk[1] +  4) ^ GETRCON( r);
    rtk[ 4*r + 2] = GETU32( tk[0] +  8) ^ GETU32( tk[1] +  8);
    rtk[ 4*r + 3] = GETU32( tk[0] + 12) ^ GETU32( tk[1] + 12);

    /* Apply H and G functions */
    H (tk[0]);
    G (tk[0], 2);

    H (tk[1]);
    G (tk[1], 1);
  }
}