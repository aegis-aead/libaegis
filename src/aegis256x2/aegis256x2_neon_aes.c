#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x2.h"
#    include "aegis256x2_neon_aes.h"

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
aegis256x2_update(aes_block_t *const state, const aes_block_t d)
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
AES_ROUND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vaesmcq_u8(vaeseq_u8(a.b0, b.b0)), vaesmcq_u8(vaeseq_u8(a.b1, b.b1)) };
}

/* T5 holds S5 XOR S4, and S3 is complemented within the bulk loop.
 * BCAX forms the output mask, and AESE recovers S5 from T5 and S4.
 * S0 is held as x0 XOR y0, separating its input XOR from the AES round on S5.
 */
static AEGIS_ALWAYS_INLINE size_t
aegis256x2_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state,
                const enum aegis_bulk_operation operation, const int store_output)
{
    const size_t      full = len - len % 32;
    const aes_block_t zero = { vmovq_n_u8(0), vmovq_n_u8(0) };
    const aes_block_t ones = { vmovq_n_u8(255), vmovq_n_u8(255) };
    aes_block_t       x0, y0, s1, s2, s3, s4, t5;
    size_t            i;

    if (full < 128) {
        return 0;
    }
    x0 = state[0];
    y0 = zero;
    s1 = state[1];
    s2 = state[2];
    s3 = AES_BLOCK_NOT(state[3]);
    s4 = state[4];
    t5 = AES_BLOCK_XOR(state[5], state[4]);

    CRYPTO_ALIGN_LOOP(64)
    for (i = 0; i < full; i += 32) {
        aes_block_t m, z, r0, r1, r4, r5;

        if (operation != AEGIS_BULK_DECRYPT) {
            r1 = AES_ROUND(x0, y0);
        }
        m = operation == AEGIS_BULK_STREAM ? zero : AES_BLOCK_LOAD(src + i);
        z = AES_BLOCK_BCAX(AES_BLOCK_XOR3(m, t5, s1), s2, s3);
        if (store_output) {
            AES_BLOCK_STORE(dst + i, z);
        }
        if (operation == AEGIS_BULK_DECRYPT) {
            m = z;
        } else if (operation == AEGIS_BULK_STREAM_XOR) {
            m = zero;
        }
        r0 = AES_ROUND(t5, s4);
        r5 = AES_ROUND(s4, zero);
        r4 = AES_ROUND(s3, ones);
        t5 = AES_BLOCK_XOR3(t5, r4, r5);
        s4 = AES_BLOCK_XOR(s4, r4);
        s3 = AES_BLOCK_XOR(s3, AES_ROUND(s2, zero));
        s2 = AES_BLOCK_XOR(s2, AES_ROUND(s1, zero));
        if (operation == AEGIS_BULK_DECRYPT) {
            r1 = AES_ROUND(x0, y0);
        }
        s1 = AES_BLOCK_XOR(s1, r1);
        x0 = AES_BLOCK_XOR3(x0, y0, m);
        y0 = r0;
    }
    state[0] = AES_BLOCK_XOR(x0, y0);
    state[1] = s1;
    state[2] = s2;
    state[3] = AES_BLOCK_NOT(s3);
    state[4] = s4;
    state[5] = AES_BLOCK_XOR(t5, s4);

    return full;
}

static AEGIS_NOINLINE size_t
aegis256x2_encrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x2_bulk(dst, src, len, state, AEGIS_BULK_ENCRYPT, 1);
}

#        define AEGIS_ENCRYPT_BULK aegis256x2_encrypt_bulk

static AEGIS_NOINLINE size_t
aegis256x2_decrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    if (dst == NULL) {
        return aegis256x2_bulk(dst, src, len, state, AEGIS_BULK_DECRYPT, 0);
    }
    return aegis256x2_bulk(dst, src, len, state, AEGIS_BULK_DECRYPT, 1);
}

#        define AEGIS_DECRYPT_BULK aegis256x2_decrypt_bulk

static AEGIS_NOINLINE size_t
aegis256x2_stream_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x2_bulk(dst, src, len, state, AEGIS_BULK_STREAM, 1);
}

#        define AEGIS_STREAM_BULK aegis256x2_stream_bulk

static AEGIS_NOINLINE size_t
aegis256x2_stream_xor_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256x2_bulk(dst, src, len, state, AEGIS_BULK_STREAM_XOR, 1);
}

#        define AEGIS_STREAM_XOR_BULK aegis256x2_stream_xor_bulk

#    endif

#    include "aegis256x2_common.h"

struct aegis256x2_implementation aegis256x2_neon_aes_implementation = {
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
