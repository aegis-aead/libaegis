#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128x4.h"
#    include "aegis128x4_armcrypto.h"

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

// Optimized for Apple Silicon's vector fusion capabilities
static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    // Direct return of computations helps avoid intermediate registers
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1), 
                           veorq_u8(a.b2, b.b2), veorq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    // Similar direct return pattern
    return (aes_block_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1), 
                           vandq_u8(a.b2, b.b2), vandq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    // Sequential loads for better utilization of memory bandwidth on Apple Silicon
    const uint8_t *a0 = a;
    const uint8_t *a1 = a + 16;
    const uint8_t *a2 = a + 32;
    const uint8_t *a3 = a + 48;
    
    return (aes_block_t) { vld1q_u8(a0), vld1q_u8(a1), vld1q_u8(a2), vld1q_u8(a3) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    // Create pattern once and reuse
    const uint8x16_t t = vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t) { t, t, t, t };
}

static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    // Sequential stores for better memory bandwidth utilization
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
    vst1q_u8(a + 32, b.b2);
    vst1q_u8(a + 48, b.b3);
}

// Specialized AES_ENC for single 128-bit block, optimized for 
// Apple Silicon's instruction fusion capabilities
static inline uint8x16_t 
AES_ENC_SINGLE_FUSED(const uint8x16_t a, const uint8x16_t b)
{
    // Apple Silicon can fuse AESE+AESMC and potentially follow-up operations
    const uint8x16_t zero = vmovq_n_u8(0);
    uint8x16_t result = vaeseq_u8(a, zero);    // AES SubBytes + ShiftRows
    result = vaesmcq_u8(result);               // AES MixColumns (fused with previous)
    return veorq_u8(result, b);                // XOR with round key (potentially fused)
}

// Super-optimized AES_ENC for 4-lane processing
// Structured for maximum instruction-level parallelism on Apple Silicon
static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    // Process all 4 blocks in parallel using our optimized single-block function
    // Using const for intermediate results to help compiler optimize
    const uint8x16_t r0 = AES_ENC_SINGLE_FUSED(a.b0, b.b0);
    const uint8x16_t r1 = AES_ENC_SINGLE_FUSED(a.b1, b.b1);
    const uint8x16_t r2 = AES_ENC_SINGLE_FUSED(a.b2, b.b2);
    const uint8x16_t r3 = AES_ENC_SINGLE_FUSED(a.b3, b.b3);
    
    // Return directly to minimize register moves
    return (aes_block_t) { r0, r1, r2, r3 };
}

// Highly optimized aegis128x4_update for Apple Silicon
// Takes full advantage of wide execution units and instruction fusion
static inline void
aegis128x4_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    // Use const for temporaries to help compiler optimize
    const aes_block_t tmp = state[7];
    
    // Compute all AES operations first to maximize parallelism
    // Using const for all temporaries helps compiler optimize register allocation
    const aes_block_t s0_enc = AES_ENC(tmp, state[0]);
    const aes_block_t s1_enc = AES_ENC(state[0], state[1]);
    const aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    const aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    const aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    const aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    const aes_block_t s6_enc = AES_ENC(state[5], state[6]);
    const aes_block_t s7_enc = AES_ENC(state[6], state[7]);
    
    // Apply XOR operations separately to allow for better instruction scheduling
    const aes_block_t s0_final = AES_BLOCK_XOR(s0_enc, d1);
    const aes_block_t s4_final = AES_BLOCK_XOR(s4_enc, d2);
    
    // Update state array in sequence for better memory access patterns
    // Apple Silicon can benefit from this sequential update pattern
    state[0] = s0_final;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_final;
    state[5] = s5_enc;
    state[6] = s6_enc;
    state[7] = s7_enc;
}

#    include "aegis128x4_common.h"

struct aegis128x4_implementation aegis128x4_armcrypto_implementation = {
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