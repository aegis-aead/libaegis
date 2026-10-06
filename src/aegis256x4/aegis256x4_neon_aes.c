#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_neon_aes.h"

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
    return (aes_block_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b0)), b.b0),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b1)), b.b1),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b2)), b.b2),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b3)), b.b3) };
}

static inline void
aegis256x4_update(aes_block_t *const state, const aes_block_t d)
{
    aes_block_t tmp;

    tmp      = state[5];
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_BLOCK_XOR(AES_ENC(tmp, state[0]), d);
}

#    ifdef AEGIS_ALWAYS_INLINE

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
} aes_pair_t;

static inline aes_pair_t
AES_PAIR_XOR(const aes_pair_t a, const aes_pair_t b)
{
    return (aes_pair_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1) };
}

static inline aes_pair_t
AES_PAIR_AND(const aes_pair_t a, const aes_pair_t b)
{
    return (aes_pair_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1) };
}

static inline aes_pair_t
AES_PAIR_LOAD(const uint8_t *a)
{
    return (aes_pair_t) { vld1q_u8(a), vld1q_u8(a + 16) };
}

static inline void
AES_PAIR_STORE(uint8_t *a, const aes_pair_t b)
{
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
}

static inline aes_pair_t
AES_PAIR_ENC(const aes_pair_t a, const aes_pair_t b)
{
    return (aes_pair_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(a.b0, vmovq_n_u8(0))), b.b0),
                          veorq_u8(vaesmcq_u8(vaeseq_u8(a.b1, vmovq_n_u8(0))), b.b1) };
}

/* Each pair of lanes evolves independently until finalization.
 * Processing pairs separately keeps the state and message in vector registers.
 */
static AEGIS_ALWAYS_INLINE size_t
aegis256x4_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state,
                const enum aegis_bulk_operation operation)
{
    const size_t full = len - len % 64;
    size_t       lane, i;

    if (full < 256) {
        return 0;
    }
    for (lane = 0; lane < 64; lane += 32) {
        aes_pair_t s0 = AES_PAIR_LOAD((const uint8_t *) &state[0] + lane);
        aes_pair_t s1 = AES_PAIR_LOAD((const uint8_t *) &state[1] + lane);
        aes_pair_t s2 = AES_PAIR_LOAD((const uint8_t *) &state[2] + lane);
        aes_pair_t s3 = AES_PAIR_LOAD((const uint8_t *) &state[3] + lane);
        aes_pair_t s4 = AES_PAIR_LOAD((const uint8_t *) &state[4] + lane);
        aes_pair_t s5 = AES_PAIR_LOAD((const uint8_t *) &state[5] + lane);

        for (i = 0; i < full; i += 64) {
            aes_pair_t m, z, t;

            if (operation == AEGIS_BULK_STREAM) {
                m = (aes_pair_t) { vmovq_n_u8(0), vmovq_n_u8(0) };
            } else {
                m = AES_PAIR_LOAD(src + i + lane);
            }
            if (operation != AEGIS_BULK_ABSORB) {
                z = AES_PAIR_XOR(AES_PAIR_XOR(s5, s4), s1);
                z = AES_PAIR_XOR(AES_PAIR_XOR(z, AES_PAIR_AND(s2, s3)), m);
                if (operation != AEGIS_BULK_DECRYPT || dst != NULL) {
                    AES_PAIR_STORE(dst + i + lane, z);
                }
                if (operation == AEGIS_BULK_DECRYPT) {
                    m = z;
                } else if (operation == AEGIS_BULK_STREAM_XOR) {
                    m = (aes_pair_t) { vmovq_n_u8(0), vmovq_n_u8(0) };
                }
            }
            t  = s5;
            s5 = AES_PAIR_ENC(s4, s5);
            s4 = AES_PAIR_ENC(s3, s4);
            s3 = AES_PAIR_ENC(s2, s3);
            s2 = AES_PAIR_ENC(s1, s2);
            s1 = AES_PAIR_ENC(s0, s1);
            s0 = AES_PAIR_XOR(AES_PAIR_ENC(t, s0), m);
        }
        AES_PAIR_STORE((uint8_t *) &state[0] + lane, s0);
        AES_PAIR_STORE((uint8_t *) &state[1] + lane, s1);
        AES_PAIR_STORE((uint8_t *) &state[2] + lane, s2);
        AES_PAIR_STORE((uint8_t *) &state[3] + lane, s3);
        AES_PAIR_STORE((uint8_t *) &state[4] + lane, s4);
        AES_PAIR_STORE((uint8_t *) &state[5] + lane, s5);
    }
    return full;
}

static AEGIS_NOINLINE size_t
aegis256x4_encrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x4_bulk(dst, src, len, state, AEGIS_BULK_ENCRYPT);
}

#        define AEGIS_ENCRYPT_BULK aegis256x4_encrypt_bulk

static AEGIS_NOINLINE size_t
aegis256x4_decrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x4_bulk(dst, src, len, state, AEGIS_BULK_DECRYPT);
}

#        define AEGIS_DECRYPT_BULK aegis256x4_decrypt_bulk

static AEGIS_NOINLINE size_t
aegis256x4_absorb_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x4_bulk(dst, src, len, state, AEGIS_BULK_ABSORB);
}

#        define AEGIS_ABSORB_BULK aegis256x4_absorb_bulk

static AEGIS_NOINLINE size_t
aegis256x4_stream_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x4_bulk(dst, src, len, state, AEGIS_BULK_STREAM);
}

#        define AEGIS_STREAM_BULK aegis256x4_stream_bulk

static AEGIS_NOINLINE size_t
aegis256x4_stream_xor_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x4_bulk(dst, src, len, state, AEGIS_BULK_STREAM_XOR);
}

#        define AEGIS_STREAM_XOR_BULK aegis256x4_stream_xor_bulk

#    endif

#    include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_neon_aes_implementation = {
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
