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

#    ifdef AEGIS_ALWAYS_INLINE

/* AESE combines the two terms of a split word before its S-box.
 * Keeping words 3 and 7 complemented also lets BCAX form the keystream.
 */
static AEGIS_ALWAYS_INLINE size_t
aegis128l_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state,
               const enum aegis_bulk_operation operation)
{
    const size_t   full         = len - len % 32;
    const unsigned split        = operation == AEGIS_BULK_ABSORB    ? 0xff
                                  : operation == AEGIS_BULK_DECRYPT ? 0x77
                                                                    : 0;
    const int      complemented = operation != AEGIS_BULK_ABSORB;
    aes_block_t    x[8], y[8], r[8];
    size_t         i, j;

    if (full < 256) {
        return 0;
    }
    for (j = 0; j < 8; j++) {
        x[j] = complemented && (j == 3 || j == 7) ? vmvnq_u8(state[j]) : state[j];
        y[j] = vmovq_n_u8(0);
    }
    CRYPTO_ALIGN_LOOP(32)
    for (i = 0; i < full; i += 32) {
        aes_block_t m0 = operation == AEGIS_BULK_STREAM ? vmovq_n_u8(0) : AES_BLOCK_LOAD(src + i);
        aes_block_t m1 =
            operation == AEGIS_BULK_STREAM ? vmovq_n_u8(0) : AES_BLOCK_LOAD(src + i + 16);

        for (j = 0; j < 8; j++) {
            const size_t prev = (j + 7) % 8;

            if (complemented && (prev == 3 || prev == 7)) {
                r[j] = vaesmcq_u8(vaeseq_u8(x[prev], vmovq_n_u8(255)));
            } else if (split & (1U << prev)) {
                r[j] = vaesmcq_u8(vaeseq_u8(x[prev], y[prev]));
            } else {
                r[j] = vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), x[prev]));
            }
        }
        for (j = 0; j < 8; j++) {
            if (split & (1U << j)) {
                x[j] = AES_BLOCK_XOR(x[j], y[j]);
            }
        }
        if (operation != AEGIS_BULK_ABSORB) {
            aes_block_t z0 = vbcaxq_u8(AES_BLOCK_XOR3(m0, x[6], x[1]), x[2], x[3]);
            aes_block_t z1 = vbcaxq_u8(AES_BLOCK_XOR3(m1, x[5], x[2]), x[6], x[7]);

            AES_BLOCK_STORE(dst + i, z0);
            AES_BLOCK_STORE(dst + i + 16, z1);
            if (operation == AEGIS_BULK_DECRYPT) {
                m0 = z0;
                m1 = z1;
            } else if (operation == AEGIS_BULK_STREAM_XOR) {
                m0 = vmovq_n_u8(0);
                m1 = vmovq_n_u8(0);
            }
        }
        for (j = 0; j < 8; j++) {
            if (split & (1U << j)) {
                y[j] = r[j];
            } else {
                x[j] = AES_BLOCK_XOR(x[j], r[j]);
            }
        }
        x[0] = AES_BLOCK_XOR(x[0], m0);
        x[4] = AES_BLOCK_XOR(x[4], m1);
    }
    for (j = 0; j < 8; j++) {
        state[j] = (split & (1U << j))                    ? AES_BLOCK_XOR(x[j], y[j])
                   : (complemented && (j == 3 || j == 7)) ? vmvnq_u8(x[j])
                                                          : x[j];
    }
    return full;
}

static AEGIS_NOINLINE size_t
aegis128l_encrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128l_bulk(dst, src, len, state, AEGIS_BULK_ENCRYPT);
}

#        define AEGIS_ENCRYPT_BULK aegis128l_encrypt_bulk

static AEGIS_NOINLINE size_t
aegis128l_decrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128l_bulk(dst, src, len, state, AEGIS_BULK_DECRYPT);
}

#        define AEGIS_DECRYPT_BULK aegis128l_decrypt_bulk

static AEGIS_NOINLINE size_t
aegis128l_absorb_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128l_bulk(dst, src, len, state, AEGIS_BULK_ABSORB);
}

#        define AEGIS_ABSORB_BULK aegis128l_absorb_bulk

static AEGIS_NOINLINE size_t
aegis128l_stream_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128l_bulk(dst, src, len, state, AEGIS_BULK_STREAM);
}

#        define AEGIS_STREAM_BULK aegis128l_stream_bulk

static AEGIS_NOINLINE size_t
aegis128l_stream_xor_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis128l_bulk(dst, src, len, state, AEGIS_BULK_STREAM_XOR);
}

#        define AEGIS_STREAM_XOR_BULK aegis128l_stream_xor_bulk

#    endif

#    include "aegis128l_common.h"

struct aegis128l_implementation aegis128l_neon_sha3_implementation = {
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
