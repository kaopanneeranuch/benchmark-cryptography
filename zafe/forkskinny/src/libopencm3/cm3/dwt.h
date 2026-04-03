#ifndef LIBOPENCM3_CM3_DWT_H
#define LIBOPENCM3_CM3_DWT_H

/* Provide minimal DWT symbols used by code when referenced, but
   for host build these are unused. */
extern unsigned DWT_CYCCNT;
extern unsigned DWT_CTRL;
#define DWT_CTRL_CYCCNTENA (1u)

#endif
