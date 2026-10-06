#if defined(__aarch64__) || defined(_M_ARM64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256.h"
#    include "aegis256_neon_aes.h"

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
#    define AES_ENC(A, B)             veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A))), (B))

static inline void
aegis256_update(aes_block_t *const state, const aes_block_t d)
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

/* Represent each state word as x ^ y.
 * AESE combines the terms, so the reconstruction XOR can run alongside the AES round.
 */
static AEGIS_ALWAYS_INLINE size_t
aegis256_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state,
              const enum aegis_bulk_operation operation)
{
    const size_t full = len - len % 16;
    size_t       i;

    if (full < 256) {
        return 0;
    }
    aes_block_t x0 = state[0], y0 = vmovq_n_u8(0);
    aes_block_t x1 = state[1], y1 = vmovq_n_u8(0);
    aes_block_t x2 = state[2], y2 = vmovq_n_u8(0);
    aes_block_t x3 = state[3], y3 = vmovq_n_u8(0);
    aes_block_t x4 = state[4], y4 = vmovq_n_u8(0);
    aes_block_t x5 = state[5], y5 = vmovq_n_u8(0);

    for (i = 0; i < full; i += 16) {
        aes_block_t m0 = operation == AEGIS_BULK_STREAM ? vmovq_n_u8(0) : AES_BLOCK_LOAD(src + i);
        aes_block_t r0 = vaesmcq_u8(vaeseq_u8(x5, y5));
        aes_block_t r1 = vaesmcq_u8(vaeseq_u8(x0, y0));
        aes_block_t r2 = vaesmcq_u8(vaeseq_u8(x1, y1));
        aes_block_t r3 = vaesmcq_u8(vaeseq_u8(x2, y2));
        aes_block_t r4 = vaesmcq_u8(vaeseq_u8(x3, y3));
        aes_block_t r5 = vaesmcq_u8(vaeseq_u8(x4, y4));

        x0 = AES_BLOCK_XOR(x0, y0);
        x1 = AES_BLOCK_XOR(x1, y1);
        x2 = AES_BLOCK_XOR(x2, y2);
        x3 = AES_BLOCK_XOR(x3, y3);
        x4 = AES_BLOCK_XOR(x4, y4);
        x5 = AES_BLOCK_XOR(x5, y5);
        if (operation != AEGIS_BULK_ABSORB) {
            aes_block_t z0 = AES_BLOCK_XOR(m0, AES_BLOCK_XOR(x5, x4));

            z0 = AES_BLOCK_XOR(z0, AES_BLOCK_XOR(x1, AES_BLOCK_AND(x2, x3)));

            AES_BLOCK_STORE(dst + i, z0);
            if (operation == AEGIS_BULK_DECRYPT) {
                m0 = z0;
            } else if (operation == AEGIS_BULK_STREAM_XOR) {
                m0 = vmovq_n_u8(0);
            }
        }
        x0 = AES_BLOCK_XOR(x0, m0);
        y0 = r0;
        y1 = r1;
        y2 = r2;
        y3 = r3;
        y4 = r4;
        y5 = r5;
    }
    state[0] = AES_BLOCK_XOR(x0, y0);
    state[1] = AES_BLOCK_XOR(x1, y1);
    state[2] = AES_BLOCK_XOR(x2, y2);
    state[3] = AES_BLOCK_XOR(x3, y3);
    state[4] = AES_BLOCK_XOR(x4, y4);
    state[5] = AES_BLOCK_XOR(x5, y5);
    return full;
}

static AEGIS_NOINLINE size_t
aegis256_encrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256_bulk(dst, src, len, state, AEGIS_BULK_ENCRYPT);
}

#        define AEGIS_ENCRYPT_BULK aegis256_encrypt_bulk

static AEGIS_NOINLINE size_t
aegis256_decrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256_bulk(dst, src, len, state, AEGIS_BULK_DECRYPT);
}

#        define AEGIS_DECRYPT_BULK aegis256_decrypt_bulk

static AEGIS_NOINLINE size_t
aegis256_absorb_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256_bulk(dst, src, len, state, AEGIS_BULK_ABSORB);
}

#        define AEGIS_ABSORB_BULK aegis256_absorb_bulk

static AEGIS_NOINLINE size_t
aegis256_stream_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256_bulk(dst, src, len, state, AEGIS_BULK_STREAM);
}

#        define AEGIS_STREAM_BULK aegis256_stream_bulk

static AEGIS_NOINLINE size_t
aegis256_stream_xor_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis256_bulk(dst, src, len, state, AEGIS_BULK_STREAM_XOR);
}

#        define AEGIS_STREAM_XOR_BULK aegis256_stream_xor_bulk

#    endif

#    include "aegis256_common.h"

struct aegis256_implementation aegis256_neon_aes_implementation = {
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
