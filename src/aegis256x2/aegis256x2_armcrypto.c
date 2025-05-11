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

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { vld1q_u8(a), vld1q_u8(a + 16) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const uint8x16_t t = vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t) { t, t };
}

static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
}

// Optimized AES_ENC for Apple Silicon with reordered operations for better instruction scheduling
static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    // Execute both AES rounds first to maximize pipeline utilization
    uint8x16_t t0 = vaeseq_u8(a.b0, vmovq_n_u8(0));
    uint8x16_t t1 = vaeseq_u8(a.b1, vmovq_n_u8(0));
    
    // Then apply MixColumns to both blocks
    t0 = vaesmcq_u8(t0);
    t1 = vaesmcq_u8(t1);
    
    // Finally XOR with b blocks
    t0 = veorq_u8(t0, b.b0);
    t1 = veorq_u8(t1, b.b1);
    
    return (aes_block_t) { t0, t1 };
}

// Optimized implementation of aegis256x2_update for Apple Silicon
static inline void
aegis256x2_update(aes_block_t *const state, const aes_block_t d)
{
    // Save state[5] before it's overwritten
    aes_block_t tmp = state[5];
    
    // Pre-compute all AES operations in parallel to maximize instruction-level parallelism
    aes_block_t s0_enc = AES_ENC(tmp, state[0]);
    aes_block_t s1_enc = AES_ENC(state[0], state[1]);
    aes_block_t s2_enc = AES_ENC(state[1], state[2]);
    aes_block_t s3_enc = AES_ENC(state[2], state[3]);
    aes_block_t s4_enc = AES_ENC(state[3], state[4]);
    aes_block_t s5_enc = AES_ENC(state[4], state[5]);
    
    // Apply XOR operation for state[0]
    s0_enc = AES_BLOCK_XOR(s0_enc, d);
    
    // Update the state array in one batch to allow for better instruction scheduling
    state[0] = s0_enc;
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