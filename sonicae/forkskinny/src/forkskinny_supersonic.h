#ifndef FORKSKINNY_SUPERSONIC_H
#define FORKSKINNY_SUPERSONIC_H

#include <stddef.h>
#include <stdint.h>

#define FORKSKINNY_SUPERSONIC_KEY_SIZE   16u
#define FORKSKINNY_SUPERSONIC_BLOCK_SIZE 16u
#define FORKSKINNY_SUPERSONIC_TAG_SIZE   32u

void supersonic_256_forkskinny(const uint8_t key[FORKSKINNY_SUPERSONIC_KEY_SIZE],
                               uint8_t out_left[FORKSKINNY_SUPERSONIC_BLOCK_SIZE],
                               uint8_t out_right[FORKSKINNY_SUPERSONIC_BLOCK_SIZE],
                               const uint8_t *message,
                               uint32_t message_len);

/* Convenience wrapper that packs out_left || out_right into a single 32-byte tag. */
void forkskinny_supersonic_tag(const uint8_t key[FORKSKINNY_SUPERSONIC_KEY_SIZE],
                               const uint8_t *message,
                               uint32_t message_len,
                               uint8_t tag[FORKSKINNY_SUPERSONIC_TAG_SIZE]);

#endif