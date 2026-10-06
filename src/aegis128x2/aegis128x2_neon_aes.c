#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128x2.h"
#    include "aegis128x2_neon_aes.h"

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

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b0)), b.b0),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), a.b1)), b.b1) };
}

static inline void
aegis128x2_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
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

#    if defined(__ARM_FEATURE_SHA3) && defined(AEGIS_ALWAYS_INLINE)

static inline aes_block_t
AES_BLOCK_NOT(const aes_block_t a)
{
    return (aes_block_t) { vmvnq_u8(a.b0), vmvnq_u8(a.b1) };
}

static inline aes_block_t
AES_BLOCK_XOR3(const aes_block_t a, const aes_block_t b, const aes_block_t c)
{
    return (aes_block_t) { veor3q_u8(a.b0, b.b0, c.b0), veor3q_u8(a.b1, b.b1, c.b1) };
}

static inline aes_block_t
AES_BLOCK_BCAX(const aes_block_t a, const aes_block_t b, const aes_block_t c)
{
    return (aes_block_t) { vbcaxq_u8(a.b0, b.b0, c.b0), vbcaxq_u8(a.b1, b.b1, c.b1) };
}

static inline aes_block_t
AES_ENC_NOT(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(a.b0, vmovq_n_u8(255))), b.b0),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(a.b1, vmovq_n_u8(255))), b.b1) };
}

static inline aes_block_t
AES_ENC_BULK(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(a.b0, vmovq_n_u8(0))), b.b0),
                           veorq_u8(vaesmcq_u8(vaeseq_u8(a.b1, vmovq_n_u8(0))), b.b1) };
}

/* Keeping S3 and S7 complemented lets BCAX combine the nonlinear output terms.
 * AESE cancels these complements with an all-ones key.
 */
static AEGIS_ALWAYS_INLINE size_t
aegis128x2_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state,
                const enum aegis_bulk_operation operation)
{
    const aes_block_t zero = { vmovq_n_u8(0), vmovq_n_u8(0) };
    const size_t      full = len - len % 64;
    aes_block_t       s0, s1, s2, s3, s4, s5, s6, s7;
    size_t            i;

    if (full < 256) {
        return 0;
    }
    s0 = state[0];
    s1 = state[1];
    s2 = state[2];
    s3 = AES_BLOCK_NOT(state[3]);
    s4 = state[4];
    s5 = state[5];
    s6 = state[6];
    s7 = AES_BLOCK_NOT(state[7]);

    for (i = 0; i < full; i += 64) {
        aes_block_t m0, m1, z0, z1, t;

        if (operation == AEGIS_BULK_STREAM) {
            m0 = zero;
            m1 = zero;
        } else {
            m0 = AES_BLOCK_LOAD(src + i);
            m1 = AES_BLOCK_LOAD(src + i + 32);
        }
        z0 = AES_BLOCK_BCAX(AES_BLOCK_XOR3(m0, s6, s1), s2, s3);
        z1 = AES_BLOCK_BCAX(AES_BLOCK_XOR3(m1, s5, s2), s6, s7);
        if (operation != AEGIS_BULK_DECRYPT || dst != NULL) {
            AES_BLOCK_STORE(dst + i, z0);
            AES_BLOCK_STORE(dst + i + 32, z1);
        }
        if (operation == AEGIS_BULK_DECRYPT) {
            m0 = z0;
            m1 = z1;
        } else if (operation == AEGIS_BULK_STREAM_XOR) {
            m0 = zero;
            m1 = zero;
        }
        t  = s7;
        s7 = AES_ENC_BULK(s6, s7);
        s6 = AES_ENC_BULK(s5, s6);
        s5 = AES_ENC_BULK(s4, s5);
        s4 = AES_BLOCK_XOR(AES_ENC_NOT(s3, s4), m1);
        s3 = AES_ENC_BULK(s2, s3);
        s2 = AES_ENC_BULK(s1, s2);
        s1 = AES_ENC_BULK(s0, s1);
        s0 = AES_BLOCK_XOR(AES_ENC_NOT(t, s0), m0);
    }
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = AES_BLOCK_NOT(s3);
    state[4] = s4;
    state[5] = s5;
    state[6] = s6;
    state[7] = AES_BLOCK_NOT(s7);

    return full;
}

static AEGIS_NOINLINE size_t
aegis128x2_encrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128x2_bulk(dst, src, len, state, AEGIS_BULK_ENCRYPT);
}

#        define AEGIS_ENCRYPT_BULK aegis128x2_encrypt_bulk

static AEGIS_NOINLINE size_t
aegis128x2_decrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128x2_bulk(dst, src, len, state, AEGIS_BULK_DECRYPT);
}

#        define AEGIS_DECRYPT_BULK aegis128x2_decrypt_bulk

static AEGIS_NOINLINE size_t
aegis128x2_stream_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128x2_bulk(dst, src, len, state, AEGIS_BULK_STREAM);
}

#        define AEGIS_STREAM_BULK aegis128x2_stream_bulk

static AEGIS_NOINLINE size_t
aegis128x2_stream_xor_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128x2_bulk(dst, src, len, state, AEGIS_BULK_STREAM_XOR);
}

#        define AEGIS_STREAM_XOR_BULK aegis128x2_stream_xor_bulk

#    endif

#    include "aegis128x2_common.h"

struct aegis128x2_implementation aegis128x2_neon_aes_implementation = {
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
