#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_armcrypto.h"

#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif

#    include <arm_neon.h>

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), \
                                     apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("+simd+crypto")
#    endif

#    define AES_BLOCK_LENGTH 64

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
    uint8x16_t b2;
    uint8x16_t b3;
} aes_block_t;

// Highly optimized for Apple Silicon's vector fusion capabilities
static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    // Direct return pattern minimizes register pressure and allows better optimization
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1), 
                           veorq_u8(a.b2, b.b2), veorq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    // Direct return for better optimization
    return (aes_block_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1), 
                           vandq_u8(a.b2, b.b2), vandq_u8(a.b3, b.b3) };
}

// Optimized load function with sequential memory access pattern
// Apple Silicon benefits from predictable memory access patterns
static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    // Using const pointers for each 16-byte chunk
    const uint8_t *a0 = a;
    const uint8_t *a1 = a + 16;
    const uint8_t *a2 = a + 32;
    const uint8_t *a3 = a + 48;
    
    // Direct return to minimize register movements
    return (aes_block_t) { vld1q_u8(a0), vld1q_u8(a1), vld1q_u8(a2), vld1q_u8(a3) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    // Create pattern once and reuse
    const uint8x16_t t = vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t) { t, t, t, t };
}

// Optimized store function with sequential memory access pattern
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    // Sequential stores for better memory bandwidth utilization
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
    vst1q_u8(a + 32, b.b2);
    vst1q_u8(a + 48, b.b3);
}

// Ultra-optimized single-block AES_ENC function
// Specifically designed for Apple Silicon's instruction fusion capabilities
static inline uint8x16_t 
AES_ENC_SINGLE_FUSED(const uint8x16_t a, const uint8x16_t b)
{
    // Pre-compute zero constant to help compiler optimize
    const uint8x16_t zero = vmovq_n_u8(0);
    
    // These operations can be fused on Apple Silicon
    uint8x16_t result = vaeseq_u8(a, zero);    // AES SubBytes + ShiftRows
    result = vaesmcq_u8(result);               // AES MixColumns (fused with previous)
    
    // This may also be fused with the previous operations
    return veorq_u8(result, b);                // XOR with round key
}

// Highly optimized AES_ENC for quad-lane processing
// Takes maximum advantage of Apple Silicon's wide execution units
static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    // Process all 4 blocks in parallel using our optimized single-block function
    // Using const for intermediate results to help compiler optimize
    const uint8x16_t r0 = AES_ENC_SINGLE_FUSED(a.b0, b.b0);
    const uint8x16_t r1 = AES_ENC_SINGLE_FUSED(a.b1, b.b1);
    const uint8x16_t r2 = AES_ENC_SINGLE_FUSED(a.b2, b.b2);
    const uint8x16_t r3 = AES_ENC_SINGLE_FUSED(a.b3, b.b3);
    
    // Direct return to minimize register movement
    return (aes_block_t) { r0, r1, r2, r3 };
}

// Maximum-performance aegis256x4_update for Apple Silicon
// Designed to fully exploit all available execution units and instruction fusion
static inline void
aegis256x4_update(aes_block_t *const state, const aes_block_t d)
{
    // Using const for temporaries to help compiler optimize
    const aes_block_t tmp = state[5];
    
    // Compute all AES operations to maximize parallelism
    // Apple Silicon has multiple execution units that can work in parallel
    // Using const for all intermediate values to reduce register pressure
    const aes_block_t s0_enc = AES_ENC(tmp, state[0]);
    const aes_block_t s1_enc = AES_ENC(state[0], state[1]);
    const aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    const aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    const aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    const aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    
    // Apply XOR operation
    // Keeping this separate for better instruction scheduling
    const aes_block_t s0_final = AES_BLOCK_XOR(s0_enc, d);
    
    // Update state array in sequential order for better cache behavior
    // This pattern helps avoid cache thrashing on Apple Silicon
    state[0] = s0_final;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_enc;
    state[5] = s5_enc;
}

#    include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_armcrypto_implementation = {
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