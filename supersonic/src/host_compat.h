#pragma once
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <x86intrin.h>

#define printk printf

typedef uint64_t timing_t;

static uint64_t _host_cpu_hz;

static inline void timing_init(void) {
    struct timespec t0, t1;
    uint64_t c0, c1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    c0 = __rdtsc();
    struct timespec end = { t0.tv_sec, t0.tv_nsec + 10000000L };
    if (end.tv_nsec >= 1000000000L) { end.tv_sec++; end.tv_nsec -= 1000000000L; }
    do { clock_gettime(CLOCK_MONOTONIC, &t1); }
    while (t1.tv_sec < end.tv_sec ||
           (t1.tv_sec == end.tv_sec && t1.tv_nsec < end.tv_nsec));
    c1 = __rdtsc();
    uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    _host_cpu_hz = (c1 - c0) * 1000000000ULL / ns;
}

static inline void timing_start(void) {}
static inline void timing_stop(void)  {}

static inline timing_t timing_counter_get(void) { return (timing_t)__rdtsc(); }

static inline uint64_t timing_cycles_get(timing_t *s, timing_t *e) { return *e - *s; }

static inline uint64_t timing_cycles_to_ns(uint64_t cycles) {
    return _host_cpu_hz ? cycles * 1000000000ULL / _host_cpu_hz : 0;
}

static inline void k_msleep(int ms) { (void)ms; }
