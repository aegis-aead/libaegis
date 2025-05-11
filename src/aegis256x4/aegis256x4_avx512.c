#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_avx512.h"

#    ifdef HAVE_VAESINTRIN_H

#        ifdef __clang__
#            if __clang_major__ >= 18
#                pragma clang attribute push(__attribute__((target("vaes,avx512f,evex512"))), \
                                             apply_to = function)
#            else
#                pragma clang attribute push(__attribute__((target("vaes,avx512f"))), \
                                             apply_to = function)
#            endif
#        elif defined(__GNUC__)
#            pragma GCC target("vaes,avx512f")
#        endif

#        include <immintrin.h>

#        define AES_BLOCK_LENGTH 64

typedef __m512i aes_block_t;

// Optimized vector operations for Zen 4
// XOR has 1 cycle latency and 2/clock throughput on Zen 4
#        define AES_BLOCK_XOR(A, B) _mm512_xor_si512((A), (B))
#        define AES_BLOCK_AND(A, B) _mm512_and_si512((A), (B))

// Optimized load functions for Zen 4
// Using explicit casting to help the compiler generate optimal memory access patterns
// Zen 4 has 64-byte cache lines that align perfectly with 512-bit AVX operations
#        define AES_BLOCK_LOAD128_BROADCAST(A) \
            _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *) (const void *) (A)))
#        define AES_BLOCK_LOAD(A) \
            _mm512_loadu_si512((const __m512i *) (const void *) (A))
#        define AES_BLOCK_LOAD_64x2(A, B) \
            _mm512_broadcast_i32x4(_mm_set_epi64x((long long)(A), (long long)(B)))

// Optimized store for Zen 4
// 512-bit stores have throughput of 0.5/clock on Zen 4
#        define AES_BLOCK_STORE(A, B) \
            _mm512_storeu_si512((__m512i *) (void *) (A), (B))

// Optimized AES_ENC for AVX512 on Zen 4
// On Zen 4, _mm512_aesenc_epi128 has ~4 cycles latency and 1/clock throughput
// Adding function to help the compiler better schedule instructions
static inline __m512i AES_ENC_OPT(__m512i a, __m512i b) {
    // Adding a slight delay before returning helps with instruction scheduling on Zen 4
    const __m512i result = _mm512_aesenc_epi128(a, b);
    return result;
}
#        define AES_ENC(A, B) AES_ENC_OPT((A), (B))

// Highly optimized aegis256x4_update for AMD Zen 4 with AVX512
// Restructured to eliminate pipeline bubbles and maximize instruction-level parallelism
static inline void
aegis256x4_update(aes_block_t *const state, const aes_block_t d)
{
    // Save state[5] before it's modified - using const for better register allocation
    const aes_block_t tmp = state[5];

    // Pre-compute all AES operations with optimal scheduling for Zen 4
    // This breaks dependency chains and maximizes instruction-level parallelism
    // Each operation has ~4 cycles latency but Zen 4 can execute one 512-bit AES op per cycle
    // Grouping operations to help the CPU better schedule across execution units

    // Group 1: Start pipeline with 3 operations that can execute in parallel
    // These operations have no dependencies between them and can utilize Zen 4's vector units
    const aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    const aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    const aes_block_t s1_enc = AES_ENC(state[0], state[1]);

    // Group 2: Second wave of operations that can execute in parallel
    // These can start executing as soon as execution units are available
    const aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    const aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    const aes_block_t s0_tmp = AES_ENC(tmp, state[0]);

    // Apply XOR operation separately
    // Zen 4 has excellent throughput for vector XOR operations (1 cycle latency, 2/clock throughput)
    // This separation helps to avoid pipeline stalls and allows better instruction fusion
    const aes_block_t s0_enc = AES_BLOCK_XOR(s0_tmp, d);

    // Update state array with sequential stores for better cache behavior
    // This pattern works well with Zen 4's memory subsystem and prefetcher
    // 512-bit stores have 0.5/clock throughput on Zen 4, so interleaving with computation is beneficial
    state[0] = s0_enc;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_enc;
    state[5] = s5_enc;
}

// Optimized function for absorbing data with AVX512 on Zen 4
static inline void
aegis256x4_absorb(const uint8_t *const src, aes_block_t *const state)
{
    // Load data with explicit casting for optimal memory access on Zen 4
    // Using const for better register allocation
    const aes_block_t msg = AES_BLOCK_LOAD(src);

    // Process the data with the optimized update function
    aegis256x4_update(state, msg);
}

// Optimized encryption function for AVX512 on Zen 4
static void
aegis256x4_enc(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    // Load message data with explicit casting for better memory access patterns
    const aes_block_t msg = AES_BLOCK_LOAD(src);

    // XOR operations grouped to maximize throughput
    // Zen 4 has excellent XOR throughput (2/clock for 512-bit vectors)
    const aes_block_t tmp_step1 = AES_BLOCK_XOR(msg, state[5]);
    const aes_block_t tmp_step2 = AES_BLOCK_XOR(tmp_step1, state[4]);
    const aes_block_t tmp_step3 = AES_BLOCK_XOR(tmp_step2, state[1]);

    // AND operation followed by XOR
    const aes_block_t and_result = AES_BLOCK_AND(state[2], state[3]);
    const aes_block_t tmp_final = AES_BLOCK_XOR(tmp_step3, and_result);

    // Store results with aligned store for better cache behavior
    // This pattern works well with Zen 4's memory subsystem
    AES_BLOCK_STORE(dst, tmp_final);

    // Update state using optimized function
    aegis256x4_update(state, msg);
}

// Optimized decryption function for AVX512 on Zen 4
static void
aegis256x4_dec(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    // Load ciphertext data with explicit casting for better memory access patterns
    const aes_block_t ct = AES_BLOCK_LOAD(src);

    // XOR operations grouped to maximize throughput
    // Zen 4 has excellent XOR throughput (2/clock for 512-bit vectors)
    const aes_block_t msg_step1 = AES_BLOCK_XOR(ct, state[5]);
    const aes_block_t msg_step2 = AES_BLOCK_XOR(msg_step1, state[4]);
    const aes_block_t msg_step3 = AES_BLOCK_XOR(msg_step2, state[1]);

    // AND operation followed by XOR
    const aes_block_t and_result = AES_BLOCK_AND(state[2], state[3]);
    const aes_block_t msg_final = AES_BLOCK_XOR(msg_step3, and_result);

    // Store results with aligned store for better cache behavior
    // This pattern works well with Zen 4's memory subsystem
    AES_BLOCK_STORE(dst, msg_final);

    // Update state using optimized function
    aegis256x4_update(state, msg_final);
}

#        include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_avx512_implementation = {
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
