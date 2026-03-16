#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_avx512.h"

#    ifdef HAVE_VAESINTRIN_H

#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target("aes,vaes,avx512f"))), \
                                         apply_to = function)
#        elif defined(__GNUC__)
#            pragma GCC target("aes,vaes,avx512f")
#        endif

#        include <immintrin.h>

#        define AES_BLOCK_LENGTH 64

typedef __m512i aes_block_t;

#        define AES_BLOCK_XOR(A, B) _mm512_xor_si512((A), (B))
#        define AES_BLOCK_AND(A, B) _mm512_and_si512((A), (B))
#        define AES_BLOCK_LOAD128_BROADCAST(A) \
            _mm512_broadcast_i32x4(_mm_loadu_si128((const void *) (A)))
#        define AES_BLOCK_LOAD(A)         _mm512_loadu_si512((const aes_block_t *) (const void *) (A))
#        define AES_BLOCK_LOAD_64x2(A, B) _mm512_broadcast_i32x4(_mm_set_epi64x((A), (B)))
#        define AES_BLOCK_STORE(A, B)     _mm512_storeu_si512((aes_block_t *) (void *) (A), (B))
#        define AES_ENC(A, B)             _mm512_aesenc_epi128((A), (B))

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

#        include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_avx512_implementation = {
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

#        ifdef __clang__
#            pragma clang attribute pop
#        endif

#    endif

#endif
