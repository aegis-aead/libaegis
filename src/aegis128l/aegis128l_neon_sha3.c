#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128l.h"
#    include "aegis128l_neon_sha3.h"

#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif
#    ifndef __ARM_FEATURE_SHA3
#        define __ARM_FEATURE_SHA3 1
#    endif

#    include <arm_neon.h>

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("neon,crypto,aes,sha3"))), \
                                     apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("+simd+crypto+sha3")
#    endif

#    define AES_BLOCK_LENGTH 16

typedef uint8x16_t aes_block_t;

#    define AES_BLOCK_XOR(A, B)       veorq_u8((A), (B))
#    define AES_BLOCK_XOR3(A, B, C)   veor3q_u8((A), (B), (C))
#    define AES_BLOCK_AND(A, B)       vandq_u8((A), (B))
#    define AES_BLOCK_LOAD(A)         vld1q_u8(A)
#    define AES_BLOCK_LOAD_64x2(A, B) vreinterpretq_u8_u64(vsetq_lane_u64((A), vmovq_n_u64(B), 1))
#    define AES_BLOCK_STORE(A, B)     vst1q_u8((A), (B))
#    define AES_ENC0(A)               vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A)))
#    define AES_ENC(A, B)             AES_BLOCK_XOR(AES_ENC0(A), (B))

static inline void
aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t tmp;

    tmp      = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_BLOCK_XOR3(state[4], AES_ENC0(state[3]), d2);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_BLOCK_XOR3(state[0], AES_ENC0(tmp), d1);
}

#    include "aegis128l_common.h"

struct aegis128l_implementation aegis128l_neon_sha3_implementation = {
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
