#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "cpu.h"

#ifndef HAVE_EXPLICIT_BZERO
#    if defined(__OpenBSD__) || defined(__FreeBSD__)
#        define HAVE_EXPLICIT_BZERO 1
#    elif defined(__GLIBC__) && defined(__GLIBC_PREREQ) && defined(__USE_MISC)
#        if __GLIBC_PREREQ(2, 25)
#            define HAVE_EXPLICIT_BZERO 1
#        endif
#    endif
#endif

#if !defined(__GNUC__) && !defined(__clang__)
static volatile uint16_t optblocker_u16;
#endif

void
aegis_secure_zero(void *buf, size_t len)
{
#if defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(buf, len);
#elif defined(__GNUC__) || defined(__clang__)
    memset(buf, 0, len);
    /* Prevent the store above from being elided as dead. */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
#else
    volatile unsigned char *p = (volatile unsigned char *) buf;
    size_t                  i;

    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
#endif
}

#if defined(__GNUC__) || defined(__clang__)
typedef uint64_t aegis_unaligned_u64 __attribute__((aligned(1), may_alias));
#endif

static inline int
aegis_verify_n(const uint8_t *x_, const uint8_t *y_, const int n)
{
    const volatile uint8_t *volatile x = (const volatile uint8_t *volatile) x_;
    const volatile uint8_t *volatile y = (const volatile uint8_t *volatile) y_;
#if !defined(__GNUC__) && !defined(__clang__)
    volatile uint16_t d;
#endif
    uint16_t acc = 0U;
    int      i   = 0;

#if defined(__GNUC__) || defined(__clang__)
    {
        const volatile aegis_unaligned_u64 *volatile x64 =
            (const volatile aegis_unaligned_u64 *volatile) (const void *) x_;
        const volatile aegis_unaligned_u64 *volatile y64 =
            (const volatile aegis_unaligned_u64 *volatile) (const void *) y_;
        uint64_t acc64 = 0U;

        for (; i + 8 <= n; i += 8) {
            acc64 |= x64[i / 8] ^ y64[i / 8];
        }
        acc64 |= acc64 >> 32;
        acc64 |= acc64 >> 16;
        acc64 |= acc64 >> 8;
        acc = (uint16_t) (acc64 & 0xff);
    }
#endif
    for (; i < n; i++) {
        acc |= x[i] ^ y[i];
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(acc) :);
    acc--;
    acc >>= 15;

    return (int) acc - 1;
#else
    d = acc;
    d--;
    d = ((d >> 13) ^ optblocker_u16) >> 2;

    return (int) d - 1;
#endif
}

int
aegis_verify_16(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 16);
}

int
aegis_verify_32(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 32);
}

extern int aegis128l_pick_best_implementation(void);
extern int aegis128x2_pick_best_implementation(void);
extern int aegis128x4_pick_best_implementation(void);
extern int aegis256_pick_best_implementation(void);
extern int aegis256x2_pick_best_implementation(void);
extern int aegis256x4_pick_best_implementation(void);

int
aegis_init(void)
{
    static int initialized = 0;

    if (initialized) {
        return 0;
    }
    if (aegis_runtime_get_cpu_features() != 0) {
        return 0;
    }
    if (aegis128l_pick_best_implementation() != 0 || aegis128x2_pick_best_implementation() != 0 ||
        aegis128x4_pick_best_implementation() != 0 || aegis256_pick_best_implementation() != 0 ||
        aegis256x2_pick_best_implementation() != 0 || aegis256x4_pick_best_implementation() != 0) {
        return -1;
    }
    initialized = 1;

    return 0;
}

#if defined(_MSC_VER)
#    pragma section(".CRT$XCU", read)
static void __cdecl _do_aegis_init(void);
__declspec(allocate(".CRT$XCU")) void (*aegis_init_constructor)(void) = _do_aegis_init;
#else
static void _do_aegis_init(void) __attribute__((constructor));
#endif

static void
_do_aegis_init(void)
{
    (void) aegis_init();
}
