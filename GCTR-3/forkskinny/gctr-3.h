#ifndef GCTR_3_H
#define GCTR_3_H

#include <stddef.h>
#include <stdint.h>

void gctr_crypt(const uint8_t *key,
				const uint8_t *iv,
				const uint8_t *in, size_t len,
				uint8_t *out);

#endif
