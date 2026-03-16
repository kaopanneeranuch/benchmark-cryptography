#include "gf.h"
#include "utils.h"

/* GF (Galois Field) multiply 
Z=X⋅Y(modx128+x7+x2+x+1)
*/
void gf_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16])
{
        uint64_t Xh = load_64(X);
        uint64_t Xl = load_64(X + 8);
        uint64_t Vh = load_64(Y);
        uint64_t Vl = load_64(Y + 8);
        uint64_t Zh = 0;
        uint64_t Zl = 0;

        for (int i = 0; i < 128; i++) {
                int bit;
                if (i < 64)
                        bit = (int)((Xh >> (63 - i)) & 1);
                else
                        bit = (int)((Xl >> (63 - (i - 64))) & 1);

                if (bit) {
                        Zh ^= Vh;
                        Zl ^= Vl;
                }

                int lsb = (int)(Vl & 1);

                uint64_t newVl = (Vl >> 1) | ((Vh & 1) << 63);
                uint64_t newVh = (Vh >> 1);
                Vh = newVh;
                Vl = newVl;

                if (lsb) {
                        Vh ^= 0xE100000000000000ULL;
                }       
        }

        store_64(out, Zh);
        store_64(out + 8, Zl);
}