#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x2.h"
#    include "aegis256x2_armcrypto.h"

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

#    define AES_BLOCK_LENGTH 32

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
} aes_block_t;

// Optimized for Apple Silicon's instruction fusion capabilities
static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    // Using direct return pattern to minimize register pressure
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    // Using direct return pattern
    return (aes_block_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    // Sequential memory access pattern for better performance on Apple Silicon
    const uint8_t *a0 = a;
    const uint8_t *a1 = a + 16;
    
    // Direct return to minimize register pressure
    return (aes_block_t) { vld1q_u8(a0), vld1q_u8(a1) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    // Generate the pattern once and reuse
    const uint8x16_t t = vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t) { t, t };
}

static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    // Sequential stores for better memory performance
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
}

// Optimized for Apple Silicon's instruction fusion capabilities
// Apple M-series chips can fuse AESE+AESMC operations
static inline uint8x16_t 
AES_ENC_SINGLE_FUSED(const uint8x16_t a, const uint8x16_t b)
{
    // Using const for zero to help compiler optimize
    const uint8x16_t zero = vmovq_n_u8(0);
    
    // These two operations can be fused on Apple Silicon
    uint8x16_t result = vaeseq_u8(a, zero);    // AES SubBytes + ShiftRows
    result = vaesmcq_u8(result);               // AES MixColumns
    
    // This XOR may also be fused with previous operations
    return veorq_u8(result, b);                // XOR with round key
}

// Highly optimized AES_ENC for dual-lane processing on Apple Silicon
// Structured for maximum instruction fusion
static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    // Process both blocks using optimized single-block function
    // Using const qualifiers to help compiler optimize register allocation
    const uint8x16_t r0 = AES_ENC_SINGLE_FUSED(a.b0, b.b0);
    const uint8x16_t r1 = AES_ENC_SINGLE_FUSED(a.b1, b.b1);
    
    // Direct return to minimize register moves
    return (aes_block_t) { r0, r1 };
}

// Super-optimized aegis256x2_update for Apple Silicon
// Maximizes instruction-level parallelism and fusion opportunities
static inline void
aegis256x2_update(aes_block_t *const state, const aes_block_t d)
{
    // Using const for temporaries to help compiler optimize
    const aes_block_t tmp = state[5];
    
    // Precompute all AES operations to maximize parallelism
    // This allows Apple Silicon to better utilize its execution units
    const aes_block_t s0_enc = AES_ENC(tmp, state[0]);
    const aes_block_t s1_enc = AES_ENC(state[0], state[1]);
    const aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    const aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    const aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    const aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    
    // Apply XOR operation for state[0]
    // Keeping this separate for better instruction scheduling
    const aes_block_t s0_final = AES_BLOCK_XOR(s0_enc, d);
    
    // Update state array using a sequential pattern
    // This helps minimize cache misses and optimize memory access
    state[0] = s0_final;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_enc;
    state[5] = s5_enc;
}

#    include "aegis256x2_common.h"

struct aegis256x2_implementation aegis256x2_armcrypto_implementation = {
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