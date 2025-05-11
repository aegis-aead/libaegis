#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128l.h"
#    include "aegis128l_armcrypto.h"

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

#    define AES_BLOCK_LENGTH 16

typedef uint8x16_t aes_block_t;

#    define AES_BLOCK_XOR(A, B)       veorq_u8((A), (B))
#    define AES_BLOCK_AND(A, B)       vandq_u8((A), (B))
#    define AES_BLOCK_LOAD(A)         vld1q_u8(A)
#    define AES_BLOCK_LOAD_64x2(A, B) vreinterpretq_u8_u64(vsetq_lane_u64((A), vmovq_n_u64(B), 1))
#    define AES_BLOCK_STORE(A, B)     vst1q_u8((A), (B))

// Optimized AES_ENC function for Apple Silicon's instruction fusion
// Apple Silicon can fuse AESE+AESMC operations and possibly adjacent vector operations
static inline uint8x16_t 
AES_ENC_FUSED(const uint8x16_t A, const uint8x16_t B)
{
    // This allows better instruction fusion on Apple Silicon
    uint8x16_t zero = vmovq_n_u8(0);
    uint8x16_t result = vaeseq_u8(A, zero);    // AES SubBytes + ShiftRows
    result = vaesmcq_u8(result);               // AES MixColumns (can be fused with previous)
    return veorq_u8(result, B);                // XOR with round key (can be fused with previous)
}

// Super-optimized aegis128l_update for Apple Silicon that maximizes 
// instruction fusion and instruction-level parallelism
static inline void
aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    // Save state[7] before it's overwritten
    const aes_block_t tmp = state[7]; 
    
    // Group all AES operations for better instruction fusion and scheduling
    // Apple Silicon can potentially fuse AESE+AESMC operations and schedule them efficiently
    
    // First compute all AES operations to maximize parallel execution
    // Use the optimized AES_ENC_FUSED function to enable instruction fusion
    const aes_block_t s0_enc = AES_ENC_FUSED(tmp, state[0]);
    const aes_block_t s1_enc = AES_ENC_FUSED(state[0], state[1]);
    const aes_block_t s2_enc = AES_ENC_FUSED(state[1], state[2]);
    const aes_block_t s3_enc = AES_ENC_FUSED(state[2], state[3]);
    const aes_block_t s4_enc = AES_ENC_FUSED(state[3], state[4]);
    const aes_block_t s5_enc = AES_ENC_FUSED(state[4], state[5]);
    const aes_block_t s6_enc = AES_ENC_FUSED(state[5], state[6]);
    const aes_block_t s7_enc = AES_ENC_FUSED(state[6], state[7]);
    
    // Compute XOR operations
    // Using const for all intermediate values helps compiler optimize
    const aes_block_t s0_final = AES_BLOCK_XOR(s0_enc, d1);
    const aes_block_t s4_final = AES_BLOCK_XOR(s4_enc, d2);
    
    // Update state array all at once to allow better instruction scheduling
    // Using a sequential update pattern for better cache behavior
    state[0] = s0_final;
    state[1] = s1_enc;
    state[2] = s2_enc;
    state[3] = s3_enc;
    state[4] = s4_final;
    state[5] = s5_enc;
    state[6] = s6_enc;
    state[7] = s7_enc;
}

#    include "aegis128l_common.h"

struct aegis128l_implementation aegis128l_armcrypto_implementation = {
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