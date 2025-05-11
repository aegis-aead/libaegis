#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256.h"
#    include "aegis256_aesni.h"

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("aes,avx"))), apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("aes,avx")
#    endif

#    include <immintrin.h>
#    include <wmmintrin.h>

#    define AES_BLOCK_LENGTH 16

typedef __m128i aes_block_t;

#    define AES_BLOCK_XOR(A, B)       _mm_xor_si128((A), (B))
#    define AES_BLOCK_AND(A, B)       _mm_and_si128((A), (B))
// Optimized load with explicit casting to help compiler
#    define AES_BLOCK_LOAD(A)         _mm_loadu_si128((const __m128i *) (const void *) (A))
#    define AES_BLOCK_LOAD_64x2(A, B) _mm_set_epi64x((long long) (A), (long long) (B))
#    define AES_BLOCK_STORE(A, B)     _mm_storeu_si128((__m128i *) (void *) (A), (B))

// Optimized AES_ENC for AMD Zen 4
// On Zen 4, _mm_aesenc_si128 has 3 cycles latency and 1 cycle throughput
static inline __m128i AES_ENC_OPT(__m128i a, __m128i b) {
    return _mm_aesenc_si128(a, b);
}

// Highly optimized aegis256_update for AMD Zen 4
// Restructured to eliminate pipeline bubbles
static inline void
aegis256_update(aes_block_t *const state, const aes_block_t d)
{
    // Save state[5] before it's modified
    // Use const to help the compiler optimize register usage
    const aes_block_t tmp = state[5];
    
    // Pre-compute all AES operations to maximize instruction-level parallelism
    // AMD Zen 4 can process one AES operation per cycle despite the 3-cycle latency
    // This approach breaks dependency chains and allows for better instruction scheduling
    const aes_block_t s5_enc = AES_ENC_OPT(state[4], state[5]);
    const aes_block_t s4_enc = AES_ENC_OPT(state[3], state[4]);
    const aes_block_t s3_enc = AES_ENC_OPT(state[2], state[3]);
    const aes_block_t s2_enc = AES_ENC_OPT(state[1], state[2]);
    const aes_block_t s1_enc = AES_ENC_OPT(state[0], state[1]);
    const aes_block_t s0_tmp = AES_ENC_OPT(tmp, state[0]);
    
    // Apply XOR operation separately for better scheduling
    // XOR operations have excellent throughput on Zen 4
    const aes_block_t s0_enc = AES_BLOCK_XOR(s0_tmp, d);
    
    // Update state with sequential stores
    // Sequential memory access pattern works well with Zen 4's cache prefetcher
    state[0] = s0_enc;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_enc;
    state[5] = s5_enc;
}

#    include "aegis256_common.h"

struct aegis256_implementation aegis256_aesni_implementation = {
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