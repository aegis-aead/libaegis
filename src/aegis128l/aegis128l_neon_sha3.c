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
#        if __GNUC__ < 14
#            pragma GCC target("arch=armv8.2-a+simd+crypto+sha3")
#        else
#            pragma GCC target("+simd+crypto+sha3")
#        endif
#    endif

#    define AES_BLOCK_LENGTH 16
#    define AES_INVERT_STATE37 1

typedef uint8x16_t aes_block_t;

static const uint8_t ones_arr[] = { 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
                                    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU };

static inline uint8x16_t fresh_ones() {
  // The AESE instruction first operand register is both an input and output to
  // the instruction. If the first operand is used in multiple places, this can
  // therefore force compilers to emit MOV instructions to duplicate the value.
  // In AES_ENC0 we use a zero register which would ordinarily have this
  // problem since the compiler can merge the zero constants together and reuse
  // them, however compilers typically treat this as a special case since
  // materializing zero is a zero-cost instruction on many micro-architectures.
  // For AES_ENC1 we cannot use this trick: materialising 0xFF is not usually
  // zero-cost so compilers do not treat it specially, however since this
  // region of the code is so heavy in vector arithmetic, inserting an
  // additional load instruction here is effectively free.
  uint8x16_t ret;
  __asm volatile("ldr %q0, %1": "=w"(ret): "m"(ones_arr));
  return ret;
}

#    define AES_BLOCK_NOT(A)          vmvnq_u8((A))
#    define AES_BLOCK_XOR(A, B)       veorq_u8((A), (B))
#    define AES_BLOCK_XNOR(A, B)      veor3q_u8((A), (B), vmovq_n_u8(0xFF))
#    define AES_BLOCK_XOR3(A, B, C)   veor3q_u8((A), (B), (C))
#    define AES_BLOCK_AND(A, B)       vandq_u8((A), (B))
#    define AES_BLOCK_LOAD(A)         vld1q_u8(A)
#    define AES_BLOCK_LOAD_64x2(A, B) vreinterpretq_u8_u64(vsetq_lane_u64((A), vmovq_n_u64(B), 1))
#    define AES_BLOCK_STORE(A, B)     vst1q_u8((A), (B))
#    define AES_ENC0(A)               vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A)))
#    define AES_ENC1(A)               vaesmcq_u8(vaeseq_u8(fresh_ones(), (A)))
#    define AES_ENC(A, B)             AES_BLOCK_XOR(AES_ENC0(A), (B))

static inline void
aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    // Apply bitwise-NOT to state[3] and state[7] to allow us to use the Arm
    // SHA3 BCAX instruction.
    aes_block_t enc7 = AES_ENC1(state[7]);
    aes_block_t enc6 = AES_ENC0(state[6]);
    aes_block_t enc5 = AES_ENC0(state[5]);
    aes_block_t enc4 = AES_ENC0(state[4]);
    aes_block_t enc3 = AES_ENC1(state[3]);
    aes_block_t enc2 = AES_ENC0(state[2]);
    aes_block_t enc1 = AES_ENC0(state[1]);
    aes_block_t enc0 = AES_ENC0(state[0]);

    state[7] = AES_BLOCK_XOR(enc6, state[7]);
    state[6] = AES_BLOCK_XOR(enc5, state[6]);
    state[5] = AES_BLOCK_XOR(enc4, state[5]);
    state[4] = AES_BLOCK_XOR3(enc3, state[4], d2);
    state[3] = AES_BLOCK_XOR(enc2, state[3]);
    state[2] = AES_BLOCK_XOR(enc1, state[2]);
    state[1] = AES_BLOCK_XOR(enc0, state[1]);
    state[0] = AES_BLOCK_XOR3(enc7, state[0], d1);
}

#    include "aegis128l_common.h"

struct aegis128l_implementation aegis128l_neon_sha3_implementation = {
    .encrypt_detached        = encrypt_detached,
    .decrypt_detached        = decrypt_detached,
    .encrypt_unauthenticated = encrypt_unauthenticated,
    .decrypt_unauthenticated = decrypt_unauthenticated,
    .stream                  = stream,
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
};

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#endif
