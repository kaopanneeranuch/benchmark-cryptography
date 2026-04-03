#include <stdint.h>
#include <string.h>
#include "stm32wrapper.h"

/* Minimal Zephyr-compatible stubs for the STM32 wrapper functions so the
 * project can build under Zephyr. These are placeholders; at runtime you
 * should provide platform-appropriate implementations. */

volatile uint32_t DWT_CYCCNT = 0;

void clock_setup(void) { }
void gpio_setup(void) { }
void usart_setup(int baud) { (void)baud; }
void send_USART_str(const char* in) { (void)in; }

void send_USART_bytes(const unsigned char* in, int n, uint64_t *cc)
{
    (void)in; (void)n; if (cc) *cc += DWT_CYCCNT; DWT_CYCCNT = 0;
}

void recv_USART_bytes(unsigned char* in, int n, uint64_t *cc)
{
    (void)cc; /* produce zeroed output */
    if (in && n > 0) memset(in, 0, (size_t)n);
    DWT_CYCCNT = 0;
}

void flash_setup(void) { }
void trigger_high(void) { }
void trigger_low(void) { }
