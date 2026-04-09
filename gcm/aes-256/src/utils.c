#include "utils.h"

/* convert 8 bytes to 64 bits with MSB to the left
b[0] is MSB and need to shift left 7 bytes (56 bits)
*/
uint64_t load_64(const uint8_t *b)
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}

void store_64(uint8_t *b, uint64_t v)
{
    b[0] = (v >> 56) & 0xff;
    b[1] = (v >> 48) & 0xff;
    b[2] = (v >> 40) & 0xff;
    b[3] = (v >> 32) & 0xff;
    b[4] = (v >> 24) & 0xff;
    b[5] = (v >> 16) & 0xff;
    b[6] = (v >> 8)  & 0xff;
    b[7] = v & 0xff;
}

void xor_block(uint8_t out[16], const uint8_t in[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] ^= in[i];
    }
}