#ifndef common_H
#define common_H

#include <stddef.h>
#include <stdint.h>

#if defined(__wasm__) && !defined(__wasi__)
static int errno;
#    define memcpy(A, B, C) __builtin_memcpy((A), (B), (C))
#    define memset(A, B, C) __builtin_memset((A), (B), (C))
#    define memcmp(A, B, C) __builtin_memcmp((A), (B), (C))
#else
#    include <errno.h>
#    include <stdlib.h>
#    include <string.h>
#endif

#include "aegis.h"

enum aegis_bulk_operation {
    AEGIS_BULK_ENCRYPT,
    AEGIS_BULK_DECRYPT,
    AEGIS_BULK_ABSORB,
    AEGIS_BULK_STREAM,
    AEGIS_BULK_STREAM_XOR
};

#ifdef __linux__
#    define HAVE_SYS_AUXV_H
#    define HAVE_GETAUXVAL
#endif
#ifdef __ANDROID_API__
#    if __ANDROID_API__ < 18
#        undef HAVE_GETAUXVAL
#        define HAVE_ANDROID_GETCPUFEATURES
#    endif
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

/* target pragmas don't define these flags on clang-cl (an alternative clang driver for Windows) */
#    if defined(__clang__) && defined(_MSC_BUILD) && defined(_MSC_VER) && \
        (defined(_M_IX86) || defined(_M_AMD64)) && !defined(__SSE3__)
#        undef __SSE3__
#        undef __SSSE3__
#        undef __SSE4_1__
#        undef __AVX__
#        undef __AVX2__
#        undef __AVX512F__
#        undef __AES__
#        undef __VAES__

#        define __SSE3__    1
#        define __SSSE3__   1
#        define __SSE4_1__  1
#        define __AVX__     1
#        define __AVX2__    1
#        define __AVX512F__ 1
#        define __AES__     1
#        define __VAES__    1
#    endif

#endif

#ifdef DISABLE_AVX2
#    undef HAVE_AVXINTRIN_H
#    undef HAVE_AVX2INTRIN_H
#    undef HAVE_AVX512FINTRIN_H
#    undef HAVE_VAESINTRIN_H
#endif
#ifdef DISABLE_AVX512
#    undef HAVE_AVX512FINTRIN_H
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

#if defined(__GNUC__) || defined(__clang__)
#    define AEGIS_ALWAYS_INLINE inline __attribute__((always_inline))
#    define AEGIS_NOINLINE      __attribute__((noinline))
#elif defined(_MSC_VER)
#    define AEGIS_ALWAYS_INLINE __forceinline
#    define AEGIS_NOINLINE      __declspec(noinline)
#endif

#if defined(__has_attribute)
#    if __has_attribute(code_align)
#        define CRYPTO_ALIGN_LOOP(x) __attribute__((code_align(x)))
#    endif
#endif
#ifndef CRYPTO_ALIGN_LOOP
#    define CRYPTO_ALIGN_LOOP(x)
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

/*
 * Overwrite a buffer that held secret material.
 *
 * Unlike memset(), this is not removable by dead-store elimination when the buffer is not read
 * again before the end of its lifetime.
 *
 * Use it only on buffers that are already in memory: caller-owned state objects, and locals whose
 * address escapes to an out-of-line call anyway. Applying it to a local that the compiler
 * currently keeps in registers -- the `aegis_blocks` scratch arrays in particular -- forces the
 * array into memory for the whole function. That defeats SROA in the hot loop and materializes
 * the very stack copy the call was meant to erase.
 */
void aegis_secure_zero(void *buf, size_t len);

#ifndef ERANGE
#    define ERANGE 34
#endif
#ifndef EINVAL
#    define EINVAL 22
#endif

#endif
