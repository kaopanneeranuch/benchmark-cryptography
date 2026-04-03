#ifndef STMWRAP_H
#define STMWRAP_H

#include <stdint.h>
#include <stdint.h>

/* When building under Zephyr (or other non-STM32 environments) avoid including
 * libopencm3 headers; provide minimal declarations so the wrapper can be
 * stubbed for testing/build. */
#ifdef __ZEPHYR__

/* Minimal DWT cycle counter symbol used by ZMAC timing code. */
extern volatile uint32_t DWT_CYCCNT;

void clock_setup(void);
void gpio_setup(void);
void usart_setup(int baud);
void send_USART_str(const char* in);
void send_USART_bytes(const unsigned char* in, int n, uint64_t *cc);
void recv_USART_bytes(unsigned char* in, int n, uint64_t *cc);
void flash_setup(void);
void trigger_high(void);
void trigger_low(void);

#else

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/cm3/scs.h>
#include <libopencm3/cm3/dwt.h>
#include <libopencm3/stm32/flash.h>

#ifdef STM32F4
#include <libopencm3/stm32/rng.h>
#endif

void clock_setup(void);
void gpio_setup(void);
void usart_setup(int baud);
void send_USART_str(const char* in);
void send_USART_bytes(const unsigned char* in, int n, uint64_t *cc);
void recv_USART_bytes(unsigned char* in, int n, uint64_t *cc);
void flash_setup(void);
void trigger_high(void);
void trigger_low(void);

#endif

void clock_setup(void);
void gpio_setup(void);
void usart_setup(int baud);
void send_USART_str(const char* in);
void send_USART_bytes(const unsigned char* in, int n, uint64_t *cc);
void recv_USART_bytes(unsigned char* in, int n, uint64_t *cc);
void flash_setup(void);
void trigger_high(void);
void trigger_low(void);

#endif
