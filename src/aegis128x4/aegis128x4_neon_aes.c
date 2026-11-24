#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128x4.h"
#    include "aegis128x4_neon_aes.h"
#    include "aegis128x4_neon_sha3.h"

#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif
#    if defined(AEGIS_NEON_SHA3) && !defined(__ARM_FEATURE_SHA3)
#        define __ARM_FEATURE_SHA3 1
#    endif

#    include <arm_neon.h>

#    ifdef AEGIS_NEON_SHA3
#        define AEGIS_NEON_IMPLEMENTATION aegis128x4_neon_sha3_implementation
#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target("neon,crypto,aes,sha3,fuse-aes"))), \
                                         apply_to = function)
#        elif defined(__GNUC__) && __GNUC__ < 14
#            pragma GCC target("arch=armv8.2-a+simd+crypto+sha3")
#        elif defined(__GNUC__)
#            pragma GCC target("+simd+crypto+sha3")
#        endif
#    else
#        define AEGIS_NEON_IMPLEMENTATION aegis128x4_neon_aes_implementation
#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target("neon,crypto,aes,fuse-aes"))), \
                                         apply_to = function)
#        elif defined(__GNUC__)
#            pragma GCC target("+simd+crypto")
#        endif
#    endif

#    define AES_BLOCK_LENGTH 64

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
    uint8x16_t b2;
    uint8x16_t b3;
} aes_block_t;

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1), veorq_u8(a.b2, b.b2),
                           veorq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1), vandq_u8(a.b2, b.b2),
                           vandq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { vld1q_u8(a), vld1q_u8(a + 16), vld1q_u8(a + 32), vld1q_u8(a + 48) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const uint8x16_t t = vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t) { t, t, t, t };
}
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
    vst1q_u8(a + 32, b.b2);
    vst1q_u8(a + 48, b.b3);
}

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(AEGIS_NEON_ZERO(), a.b0)), b.b0),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(AEGIS_NEON_ZERO(), a.b1)), b.b1),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(AEGIS_NEON_ZERO(), a.b2)), b.b2),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(AEGIS_NEON_ZERO(), a.b3)), b.b3) };
}

static inline void
aegis128x4_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t tmp;

    tmp      = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_BLOCK_XOR(AES_ENC(state[3], state[4]), d2);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_BLOCK_XOR(AES_ENC(tmp, state[0]), d1);
}

#    ifdef AEGIS_ALWAYS_INLINE
#        include "../common/neon_lane.h"
#        define AEGIS_LANES_WORDS 8
#        include "../common/aegis_lanes.h"
#    endif

#    include "aegis128x4_common.h"

struct aegis128x4_implementation AEGIS_NEON_IMPLEMENTATION = {
    .encrypt_detached        = encrypt_detached,
    .decrypt_detached        = decrypt_detached,
    .encrypt_unauthenticated = encrypt_unauthenticated,
    .decrypt_unauthenticated = decrypt_unauthenticated,
    .stream                  = stream,
    .stream_xor              = stream_xor,
    .state_init              = state_init,
    .state_encrypt_update    = state_encrypt_update,
    .state_encrypt_final     = state_encrypt_final,
    .state_decrypt_update    = state_decrypt_update,
    .state_decrypt_final     = state_decrypt_final,
    .state_mac_init          = state_mac_init,
    .state_mac_update        = state_mac_update,
    .state_mac_final         = state_mac_final,
    .state_mac_reset         = state_mac_reset,
    .state_mac_clone         = state_mac_clone,
    .state_mac_verify        = state_mac_verify,
};

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#endif
