#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256.h"
#    include "aegis256_aesni.h"

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("aes,avx"))), apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("aes,avx")
#    endif

#    include <immintrin.h>
#    include <wmmintrin.h>

#    define AES_BLOCK_LENGTH 16

typedef __m128i aes_block_t;

#    define AES_BLOCK_XOR(A, B)       _mm_xor_si128((A), (B))
#    define AES_BLOCK_AND(A, B)       _mm_and_si128((A), (B))
#    define AES_BLOCK_LOAD(A)         _mm_loadu_si128((const aes_block_t *) (const void *) (A))
#    define AES_BLOCK_LOAD_64x2(A, B) _mm_set_epi64x((long long) (A), (long long) (B))
#    define AES_BLOCK_STORE(A, B)     _mm_storeu_si128((aes_block_t *) (void *) (A), (B))
#    define AES_ENC(A, B)             _mm_aesenc_si128((A), (B))

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

/*
 * AESENC(s5, 0) ^ (s0 ^ m) is the same as AESENC(s5, s0) ^ m, but the next s0 doesn't have to wait for a full AES round.
 * 32-bit x86 doesn't have enough registers for it.
 */
#    if defined(AEGIS_ALWAYS_INLINE) && (defined(__x86_64__) || defined(_M_AMD64))

static AEGIS_NOINLINE size_t
aegis256_mac_absorb_run(const uint8_t *src, size_t len, aes_block_t *state)
{
    const size_t  full = len - len % AES_BLOCK_LENGTH;
    const __m128i zero = _mm_setzero_si128();
    __m128i       s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3], s4 = state[4],
                  s5 = state[5];
    size_t        i;

    for (i = 0; i < full; i += AES_BLOCK_LENGTH) {
        const __m128i m  = AES_BLOCK_LOAD(src + i);
        const __m128i n0 = AES_ENC(s5, zero);

        s5 = AES_ENC(s4, s5);
        s4 = AES_ENC(s3, s4);
        s3 = AES_ENC(s2, s3);
        s2 = AES_ENC(s1, s2);
        s1 = AES_ENC(s0, s1);
        s0 = AES_BLOCK_XOR(n0, AES_BLOCK_XOR(s0, m));
    }
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
    state[4] = s4;
    state[5] = s5;

    return full;
}

static inline size_t
aegis256_mac_absorb_bulk(const uint8_t *src, size_t len, aes_block_t *state)
{
    aes_block_t copy[6];
    size_t      n;

    if (len < 2048) {
        return 0;
    }
    memcpy(copy, state, sizeof copy);
    n = aegis256_mac_absorb_run(src, len, copy);
    memcpy(state, copy, sizeof copy);

    return n;
}

#        define AEGIS_MAC_ABSORB_BULK(dst, src, len, state) \
            aegis256_mac_absorb_bulk((src), (len), (state))
#    endif

#    include "aegis256_common.h"

struct aegis256_implementation aegis256_aesni_implementation = {
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
