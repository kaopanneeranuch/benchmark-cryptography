#ifndef FENC_H
#define FENC_H

#include <stddef.h>
#include <stdint.h>

void fenc(const uint8_t *key,
				const uint8_t *iv,
				const uint8_t *in, size_t len,
				uint8_t *out);

#endif
