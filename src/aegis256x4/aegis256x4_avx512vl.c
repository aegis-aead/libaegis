#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_avx512vl.h"

#    ifdef HAVE_VAESINTRIN_H

#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target("aes,vaes,avx512f,avx512vl"))), \
                                         apply_to = function)
#        elif defined(__GNUC__)
#            pragma GCC target("aes,vaes,avx512f,avx512vl")
#        endif

#        include <immintrin.h>

#        define AES_BLOCK_LENGTH 64

/* Some CPUs run 512-bit AVX-512 instructions as two 256-bit passes internally.
 * Splitting the state into real 256-bit halves gives those CPUs twice as many independent chains to
 * work with, and AVX-512VL still gets us the extra registers and ternary-logic instructions
 * full-width AVX-512 would have. */
typedef struct {
    __m256i b0;
    __m256i b1;
} aes_block_t;

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { _mm256_xor_si256(a.b0, b.b0), _mm256_xor_si256(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_XOR3(const aes_block_t a, const aes_block_t b, const aes_block_t c)
{
    return (aes_block_t) { _mm256_ternarylogic_epi64(a.b0, b.b0, c.b0, 0x96),
                           _mm256_ternarylogic_epi64(a.b1, b.b1, c.b1, 0x96) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { _mm256_and_si256(a.b0, b.b0), _mm256_and_si256(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { _mm256_loadu_si256((const __m256i *) (const void *) a),
                           _mm256_loadu_si256((const __m256i *) (const void *) (a + 32)) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m256i t = _mm256_broadcastsi128_si256(_mm_set_epi64x((long long) a, (long long) b));
    return (aes_block_t) { t, t };
}

static inline aes_block_t
aes_block_broadcast128(const uint8_t *a)
{
    const __m256i t =
        _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) (const void *) a));
    return (aes_block_t) { t, t };
}

#        define AES_BLOCK_BROADCAST128(A) aes_block_broadcast128(A)

static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    _mm256_storeu_si256((__m256i *) (void *) a, b.b0);
    _mm256_storeu_si256((__m256i *) (void *) (a + 32), b.b1);
}

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { _mm256_aesenc_epi128(a.b0, b.b0), _mm256_aesenc_epi128(a.b1, b.b1) };
}

static inline aes_block_t
AES_ENC0(const aes_block_t a)
{
    return (aes_block_t) { _mm256_aesenc_epi128(a.b0, _mm256_setzero_si256()),
                           _mm256_aesenc_epi128(a.b1, _mm256_setzero_si256()) };
}

static inline void
aegis256x4_update(aes_block_t *const state, const aes_block_t d)
{
    aes_block_t tmp;

    tmp      = state[5];
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    /* AESENC(x, k) is the same as AESENC(x, 0) XORed with k.
     * That lets this round start without waiting on the earlier XOR, and folds the two XORs into
     * one instruction. */
    state[0] = AES_BLOCK_XOR3(AES_ENC0(tmp), state[0], d);
}

#        define AEGIS256X4_UPDATE_NODATA_DEFINED
static inline void
aegis256x4_update_nodata(aes_block_t *const state)
{
    aes_block_t tmp;

    tmp      = state[5];
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);
}

/* 32 vector registers: four blocks in flight pay off here. */
#        if defined(__x86_64__) || defined(_M_AMD64)
#            define AEGIS_UNROLL_X4 1
#        endif

#        include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_avx512vl_implementation = {
    .encrypt_detached        = encrypt_detached,
    .decrypt_detached        = decrypt_detached,
    .encrypt_unauthenticated = encrypt_unauthenticated,
    .decrypt_unauthenticated = decrypt_unauthenticated,
    .stream                  = stream,
    .stream_xor              = stream_xor,
    .state_init              = state_init,
    .state_encrypt_update    = state_encrypt_update,
    .state_encrypt_final     = state_encrypt_final,
    .state_decrypt_update    = state_decrypt_update,
    .state_decrypt_final     = state_decrypt_final,
    .state_mac_init          = state_mac_init,
    .state_mac_update        = state_mac_update,
    .state_mac_final         = state_mac_final,
    .state_mac_reset         = state_mac_reset,
    .state_mac_clone         = state_mac_clone,
    .state_mac_verify        = state_mac_verify,
};

#        ifdef __clang__
#            pragma clang attribute pop
#        endif

#    endif

#endif
