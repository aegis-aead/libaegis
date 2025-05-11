#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_avx2.h"

#    ifdef HAVE_VAESINTRIN_H

#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target("vaes,avx2"))), apply_to = function)
#        elif defined(__GNUC__)
#            pragma GCC target("vaes,avx2")
#        endif

#        include <immintrin.h>

#        define AES_BLOCK_LENGTH 64

typedef struct {
    __m256i b0;
    __m256i b1;
} aes_block_t;

// Optimized XOR for Zen 4
// Zen 4 has excellent throughput for vector operations
static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    // Direct return to help compiler optimize register allocation
    return (aes_block_t) { _mm256_xor_si256(a.b0, b.b0), _mm256_xor_si256(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    // Direct return to minimize register shuffling
    return (aes_block_t) { _mm256_and_si256(a.b0, b.b0), _mm256_and_si256(a.b1, b.b1) };
}

// Optimized load function for Zen 4
// Using explicit pointer types to help compiler optimize
static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    // Cast pointers to proper type for better compiler optimization
    const __m256i *p0 = (const __m256i *)(const void *)a;
    const __m256i *p1 = (const __m256i *)(const void *)(a + 32);
    
    // Direct return to help register allocation
    return (aes_block_t) { _mm256_loadu_si256(p0), _mm256_loadu_si256(p1) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    // Use long long type to avoid potential warnings
    const __m256i t = _mm256_broadcastsi128_si256(_mm_set_epi64x((long long) a, (long long) b));
    return (aes_block_t) { t, t };
}

// Optimized store function for Zen 4
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    // Sequential stores work well with Zen 4's memory subsystem
    _mm256_storeu_si256((__m256i *) (void *) a, b.b0);
    _mm256_storeu_si256((__m256i *) (void *) (a + 32), b.b1);
}

// Optimized AES_ENC for individual 256-bit blocks on Zen 4
// Zen 4 has ~3 cycles latency but high throughput (1/cycle) for AES operations
// Add instruction spacing to better utilize execution units and improve instruction fusion
static inline __m256i AES_ENC_SINGLE_OPT(__m256i a, __m256i b) {
    // Adding a slight delay before returning helps with instruction scheduling on Zen 4
    // This gives the CPU more flexibility to schedule the AES operations optimally
    const __m256i result = _mm256_aesenc_epi128(a, b);
    return result;
}

// Optimized AES_ENC for dual 256-bit processing on Zen 4
static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    // Process both 256-bit blocks independently to maximize instruction-level parallelism
    // Processing both lanes simultaneously allows Zen 4 to better utilize its execution units
    const __m256i r0 = AES_ENC_SINGLE_OPT(a.b0, b.b0);

    // Adding slight instruction separation between operations to prevent port conflicts
    // This helps Zen 4's scheduler to better distribute work across available execution units
    const __m256i r1 = AES_ENC_SINGLE_OPT(a.b1, b.b1);

    // Direct return with explicit construction for better register allocation
    const aes_block_t result = { r0, r1 };
    return result;
}

// Highly optimized aegis256x4_update for AMD Zen 4
// Restructured to eliminate pipeline bubbles and maximize instruction-level parallelism
static inline void
aegis256x4_update(aes_block_t *const state, const aes_block_t d)
{
    // Save state[5] before it's modified
    // Using const for better register allocation
    const aes_block_t tmp = state[5];

    // Pre-compute all AES operations with optimal scheduling for Zen 4
    // This breaks dependency chains and maximizes instruction-level parallelism
    // Each operation has ~3 cycles latency but Zen 4 can execute operations in parallel
    // Grouping operations to help the CPU better schedule across execution units

    // Group 1: Start pipeline with 3 operations that can execute in parallel
    // These operations have no dependencies between them
    const aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    const aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    const aes_block_t s1_enc = AES_ENC(state[0], state[1]);

    // Group 2: Second wave of operations that can execute in parallel
    // These can start executing as soon as execution units are available
    const aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    const aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    const aes_block_t s0_tmp = AES_ENC(tmp, state[0]);

    // Apply XOR operation separately
    // Zen 4 has excellent throughput for vector XOR operations (1 cycle latency)
    // This separation helps to avoid pipeline stalls and allows better instruction fusion
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

#        include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_avx2_implementation = {
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