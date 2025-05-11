#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128x2.h"
#    include "aegis128x2_aesni.h"

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("aes,avx"))), apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("aes,avx")
#    endif

#    include <immintrin.h>
#    include <wmmintrin.h>

#    define AES_BLOCK_LENGTH 32

typedef struct {
    __m128i b0;
    __m128i b1;
} aes_block_t;

// Optimized XOR for AMD Zen 4
// Zen 4 has 1-cycle latency and 0.33-cycle throughput for _mm_xor_si128
static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    // Direct return helps compiler optimize better
    return (aes_block_t) { _mm_xor_si128(a.b0, b.b0), _mm_xor_si128(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    // Direct return pattern
    return (aes_block_t) { _mm_and_si128(a.b0, b.b0), _mm_and_si128(a.b1, b.b1) };
}

// Optimized load function for AMD Zen 4
// Using explicit pointers to help the compiler schedule loads better
static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    const __m128i *p0 = (const __m128i *)(const void *)a;
    const __m128i *p1 = (const __m128i *)(const void *)(a + 16);
    
    // Zen 4 has good support for unaligned loads
    return (aes_block_t) { _mm_loadu_si128(p0), _mm_loadu_si128(p1) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const __m128i t = _mm_set_epi64x((long long) a, (long long) b);
    return (aes_block_t) { t, t };
}

// Optimized store for AMD Zen 4
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    // Using sequential stores which perform well on Zen 4
    _mm_storeu_si128((__m128i *) (void *) a, b.b0);
    _mm_storeu_si128((__m128i *) (void *) (a + 16), b.b1);
}

// Optimized AES_ENC for AMD Zen 4
// Zen 4 has 3-cycle latency and 1-cycle throughput for _mm_aesenc_si128
static inline __m128i AES_ENC_SINGLE_OPT(__m128i a, __m128i b) {
    return _mm_aesenc_si128(a, b);
}

// Highly optimized AES_ENC for dual-lane processing
static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    // Process both lanes independently to maximize throughput
    const __m128i r0 = AES_ENC_SINGLE_OPT(a.b0, b.b0);
    const __m128i r1 = AES_ENC_SINGLE_OPT(a.b1, b.b1);
    
    // Direct return to minimize register shuffling
    return (aes_block_t) { r0, r1 };
}

// Optimized aegis128x2_update for AMD Zen 4
// Restructured for maximum throughput with Zen 4's execution units
static inline void
aegis128x2_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    // Save state[7] before modification - using const to help compiler optimize
    const aes_block_t tmp = state[7];
    
    // Pre-compute all AES operations
    // This breaks the dependency chain and allows Zen 4 to fill its execution pipeline
    // Zen 4 can execute one AES operation per cycle despite the 3-cycle latency
    const aes_block_t s7_enc = AES_ENC(state[6], state[7]);
    const aes_block_t s6_enc = AES_ENC(state[5], state[6]);
    const aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    const aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    const aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    const aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    const aes_block_t s1_enc = AES_ENC(state[0], state[1]);
    const aes_block_t s0_enc = AES_ENC(tmp, state[0]);
    
    // Apply XOR operations separately
    // Zen 4 excels at these simple vector operations
    const aes_block_t s0_final = AES_BLOCK_XOR(s0_enc, d1);
    const aes_block_t s4_final = AES_BLOCK_XOR(s4_enc, d2);
    
    // Update state using sequential stores
    // Sequential access pattern works well with Zen 4's cache prefetcher
    state[0] = s0_final;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_final;
    state[5] = s5_enc;
    state[6] = s6_enc;
    state[7] = s7_enc;
}

#    include "aegis128x2_common.h"

struct aegis128x2_implementation aegis128x2_aesni_implementation = {
    .encrypt_detached              = encrypt_detached,
    .decrypt_detached              = decrypt_detached,
    .encrypt_unauthenticated       = encrypt_unauthenticated,
    .decrypt_unauthenticated       = decrypt_unauthenticated,
    .stream                        = stream,
    .state_init                    = state_init,
    .state_encrypt_update          = state_encrypt_update,
    .state_encrypt_detached_final  = state_encrypt_detached_final,
    .state_encrypt_final           = state_encrypt_final,
    .state_decrypt_detached_update = state_decrypt_detached_update,
    .state_decrypt_detached_final  = state_decrypt_detached_final,
    .state_mac_init                = state_mac_init,
    .state_mac_update              = state_mac_update,
    .state_mac_final               = state_mac_final,
    .state_mac_reset               = state_mac_reset,
    .state_mac_clone               = state_mac_clone,
};

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#endif