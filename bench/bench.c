/*
 * Reel-256 (c/opt) encryption throughput, in GB/s and in core cycles per
 * byte. Cycles come from the clock measured next to each timing with a
 * chain of dependent adds, one per cycle on the cores we know; this keeps
 * the figure meaningful on laptops that throttle. Best of 7 rounds.
 */
#define _POSIX_C_SOURCE 200809L /* clock_gettime under -std=c11 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "reel.h"

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static double ghz(void) {
    unsigned long x = 0, n = 40000000UL;
    double t = now();
    for (unsigned long i = 0; i < n; i += 8)
#if defined(__x86_64__)
        __asm__ volatile("add $1,%0\n\tadd $1,%0\n\tadd $1,%0\n\tadd $1,%0\n\t"
                         "add $1,%0\n\tadd $1,%0\n\tadd $1,%0\n\tadd $1,%0" : "+r"(x));
#else
        __asm__ volatile("add %0,%0,#1\n\tadd %0,%0,#1\n\tadd %0,%0,#1\n\tadd %0,%0,#1\n\t"
                         "add %0,%0,#1\n\tadd %0,%0,#1\n\tadd %0,%0,#1\n\tadd %0,%0,#1" : "+r"(x));
#endif
    return n / (now() - t) / 1e9;
}

int main(void) {
    static const size_t sizes[] = {64, 576, 1420, 16384, 65536};
    static uint8_t key[32], nonce[16], ad[16], tag[16];
    uint8_t *msg = calloc(1, 65536), *out = malloc(65536);
    if (!msg || !out) return 1;
    printf("%8s %10s %12s\n", "bytes", "GB/s", "cycles/byte");
    for (size_t z = 0; z < sizeof sizes / sizeof *sizes; z++) {
        size_t len = sizes[z], iters = (size_t)(1e8 / (len + 64));
        double best_gbps = 0, best_cpb = 1e9;
        for (int r = 0; r < 7; r++) {
            for (size_t i = 0; i < iters / 20; i++)
                reel256_encrypt(out, tag, msg, len, ad, sizeof ad, key, nonce);
            double f0 = ghz(), t0 = now();
            for (size_t i = 0; i < iters; i++)
                reel256_encrypt(out, tag, msg, len, ad, sizeof ad, key, nonce);
            double secs = now() - t0, bytes = (double)len * iters;
            double cpb = (f0 + ghz()) / 2 * 1e9 * secs / bytes;
            if (bytes / secs / 1e9 > best_gbps) best_gbps = bytes / secs / 1e9;
            if (cpb < best_cpb) best_cpb = cpb;
        }
        printf("%8zu %10.2f %12.3f\n", len, best_gbps, best_cpb);
    }
    return 0;
}
