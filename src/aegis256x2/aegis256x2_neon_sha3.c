#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x2.h"
#    include "aegis256x2_neon_sha3.h"

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

#    define AES_BLOCK_LENGTH 32
#    define AES_INVERT_STATE3 1

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
} aes_block_t;

static const uint8_t ones_arr[] = { 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
                                    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
                                    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
                                    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU };

static inline uint8x16x2_t
fresh_ones_pair(void)
{
    // The AESE instruction first operand register is both an input and output
    // to the instruction. If the first operand is used in multiple places,
    // this can therefore force compilers to emit MOV instructions to duplicate
    // the value. In AES_ENC0 we use a zero register which would ordinarily
    // have this problem since the compiler can merge the zero constants
    // together and reuse them, however compilers typically treat this as a
    // special case since materializing zero is a zero-cost instruction on many
    // micro-architectures. For AES_ENC1 we cannot use this trick:
    // materializing 0xFF is not usually zero-cost so compilers do not treat it
    // specially, however since this region of the code is so heavy in vector
    // arithmetic, inserting an additional load instruction here is
    // effectively free.
    uint8x16x2_t ret;
    __asm volatile("ldp %q0, %q1, [%2]": "=w"(ret.val[0]), "=w"(ret.val[1]): "r"(ones_arr));
    return ret;
}

static inline aes_block_t
AES_BLOCK_NOT(const aes_block_t a)
{
    return (aes_block_t) { vmvnq_u8(a.b0), vmvnq_u8(a.b1) };
}

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1) };
}

static inline aes_block_t
AES_BLOCK_XNOR(const aes_block_t a, const aes_block_t b)
{
    const uint8x16_t ones = vmovq_n_u8(0xff);

    return (aes_block_t) { veor3q_u8(a.b0, b.b0, ones), veor3q_u8(a.b1, b.b1, ones) };
}

static inline aes_block_t
AES_BLOCK_XOR3(const aes_block_t a, const aes_block_t b, const aes_block_t c)
{
    return (aes_block_t) { veor3q_u8(a.b0, b.b0, c.b0), veor3q_u8(a.b1, b.b1, c.b1) };
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

static inline aes_block_t
AES_ENC0(const aes_block_t a)
{
    return (aes_block_t) { vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b0)),
                           vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b1)) };
}

static inline aes_block_t
AES_ENC1(const aes_block_t a)
{
    uint8x16x2_t ones = fresh_ones_pair();
    return (aes_block_t) { vaesmcq_u8(vaeseq_u8(ones.val[0], a.b0)),
                           vaesmcq_u8(vaeseq_u8(ones.val[1], a.b1)) };
}

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return AES_BLOCK_XOR(AES_ENC0(a), b);
}

static inline void
aegis256x2_update(aes_block_t *const state, const aes_block_t d)
{
    aes_block_t tmp = state[5];

    // Apply bitwise-NOT to state[3] to allow us to use the Arm SHA3 BCAX
    // instruction.
    state[5] = AES_BLOCK_XOR(AES_ENC0(state[4]), state[5]);
    state[4] = AES_BLOCK_XOR(AES_ENC1(state[3]), state[4]);
    state[3] = AES_BLOCK_XOR(AES_ENC0(state[2]), state[3]);
    state[2] = AES_BLOCK_XOR(AES_ENC0(state[1]), state[2]);
    state[1] = AES_BLOCK_XOR(AES_ENC0(state[0]), state[1]);
    state[0] = AES_BLOCK_XOR3(AES_ENC0(tmp), state[0], d);
}

#    include "aegis256x2_common.h"

struct aegis256x2_implementation aegis256x2_neon_sha3_implementation = {
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
