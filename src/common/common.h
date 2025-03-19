#ifndef common_H
#define common_H

#include <stddef.h>
#include <stdint.h>

#if defined(__wasm__) && !defined(__wasi__)
static int errno;
#    define memcpy(A, B, C) __builtin_memcpy((A), (B), (C));
#    define memset(A, B, C) __builtin_memset((A), (B), (C));
#else
#    include <errno.h>
#    include <stdlib.h>
#    include <string.h>
#endif

#include "aegis.h"

#ifdef __linux__
#    define HAVE_SYS_AUXV_H
#    define HAVE_GETAUXVAL
#endif
#ifdef __ANDROID_API__
#    if __ANDROID_API__ < 18
#        undef HAVE_GETAUXVAL
#    endif
#    define HAVE_ANDROID_GETCPUFEATURES
#endif
#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)
#    define HAVE_CPUID
#    define NATIVE_LITTLE_ENDIAN
#    if defined(__clang__) || defined(__GNUC__)
#        define HAVE_AVX_ASM
#    endif
#    define HAVE_AVXINTRIN_H
#    define HAVE_AVX2INTRIN_H
#    define HAVE_AVX512FINTRIN_H
#    define HAVE_TMMINTRIN_H
#    define HAVE_WMMINTRIN_H
#    define HAVE_VAESINTRIN_H
#    ifdef __GNUC__
#        if !__has_include(<vaesintrin.h>)
#            undef HAVE_VAESINTRIN_H
#        endif
#    endif
#endif

#if defined(__clang__) && defined(_MSC_VER)
#    define __AVX__ 1
#    define __AVX2__ 1
#    define __AVX512F__ 1
#    define __VAES__ 1
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    ifndef NATIVE_LITTLE_ENDIAN
#        define NATIVE_LITTLE_ENDIAN
#    endif
#endif

#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#    define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#    define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] << 8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

#define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#ifndef ERANGE
#    define ERANGE 34
#endif
#ifndef EINVAL
#    define EINVAL 22
#endif

#endif
