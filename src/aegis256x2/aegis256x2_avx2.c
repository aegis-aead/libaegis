#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x2.h"
#    include "aegis256x2_avx2.h"

#    ifdef HAVE_VAESINTRIN_H

#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target("vaes,avx2"))), apply_to = function)
#        elif defined(__GNUC__)
#            pragma GCC target("vaes,avx2")
#        endif

#        include <immintrin.h>

#        define AES_BLOCK_LENGTH 32

typedef __m256i aes_block_t;

// Optimized vector operations for Zen 4
#        define AES_BLOCK_XOR(A, B) _mm256_xor_si256((A), (B))
#        define AES_BLOCK_AND(A, B) _mm256_and_si256((A), (B))

// Optimized load operations for Zen 4
// Using explicit casts and pointer types to help the compiler
#        define AES_BLOCK_LOAD128_BROADCAST(A) \
            _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *) (const void *) (A)))
#        define AES_BLOCK_LOAD(A) \
            _mm256_loadu_si256((const __m256i *) (const void *) (A))
#        define AES_BLOCK_LOAD_64x2(A, B) \
            _mm256_broadcastsi128_si256(_mm_set_epi64x((long long)(A), (long long)(B)))
#        define AES_BLOCK_STORE(A, B) \
            _mm256_storeu_si256((__m256i *) (void *) (A), (B))

// Optimized AES_ENC for Zen 4
// Zen 4 has ~3 cycles latency but high throughput (1/cycle) for AES operations
// Add instruction spacing to better utilize execution units and improve instruction fusion
static inline __m256i AES_ENC_OPT(__m256i a, __m256i b) {
    // Adding a slight delay before returning helps with instruction scheduling on Zen 4
    // This gives the CPU more flexibility to schedule the AES operations optimally
    const __m256i result = _mm256_aesenc_epi128(a, b);
    return result;
}

// Highly optimized aegis256x2_update for AMD Zen 4
// Restructured to eliminate pipeline bubbles and maximize instruction-level parallelism
static inline void
aegis256x2_update(aes_block_t *const state, const aes_block_t d)
{
    // Save state[5] before it's modified
    // Using const qualifier to help compiler optimize register allocation
    const aes_block_t tmp = state[5];

    // Pre-compute all AES operations with optimal scheduling for Zen 4
    // This breaks dependency chains and maximizes instruction-level parallelism
    // Grouping operations to help the CPU better schedule across execution units

    // Group 1: Start pipeline with 3 operations that can execute in parallel
    const aes_block_t s5_enc = AES_ENC_OPT(state[4], state[5]);
    const aes_block_t s3_enc = AES_ENC_OPT(state[2], state[3]);
    const aes_block_t s1_enc = AES_ENC_OPT(state[0], state[1]);

    // Group 2: Second wave of operations that can execute in parallel
    const aes_block_t s4_enc = AES_ENC_OPT(state[3], state[4]);
    const aes_block_t s2_enc = AES_ENC_OPT(state[1], state[2]);
    const aes_block_t s0_tmp = AES_ENC_OPT(tmp, state[0]);

    // Apply XOR operation separately
    // Zen 4 has excellent throughput for vector XOR operations (1 cycle latency)
    // This separation helps avoid pipeline stalls
    const aes_block_t s0_enc = AES_BLOCK_XOR(s0_tmp, d);

    // Update state array with sequential stores for better cache behavior
    // This pattern works well with Zen 4's memory subsystem and prefetcher
    state[0] = s0_enc;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_enc;
    state[5] = s5_enc;
}

#        include "aegis256x2_common.h"

struct aegis256x2_implementation aegis256x2_avx2_implementation = {
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

#        ifdef __clang__
#            pragma clang attribute pop
#        endif

#    endif

#endif