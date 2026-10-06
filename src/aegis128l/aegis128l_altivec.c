#if defined(__ALTIVEC__) && defined(__CRYPTO__)

#    include <stddef.h>
#    include <stdint.h>

#    include "../common/common.h"
#    include "aegis128l.h"
#    include "aegis128l_altivec.h"

#    include <altivec.h>

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("altivec,crypto"))), apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("altivec,crypto")
#    endif

#    define AES_BLOCK_LENGTH 16

typedef vector unsigned char aes_block_t;

#    define AES_BLOCK_XOR(A, B) vec_xor((A), (B))
#    define AES_BLOCK_AND(A, B) vec_and((A), (B))
#    define AES_BLOCK_LOAD(A)   vec_xl_be(0, (const unsigned char *) (A))
#    define AES_BLOCK_LOAD_64x2(A, B) \
        ((aes_block_t) vec_revb(vec_insert((A), vec_promote((unsigned long long) (B), 1), 0)))
#    define AES_BLOCK_STORE(A, B) vec_xst_be((B), 0, (unsigned char *) (A))
#    define AES_ENC(A, B)         ((aes_block_t) vec_cipher_be((A), (B)))

static inline void
aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
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

#    include "aegis128l_common.h"

struct aegis128l_implementation aegis128l_altivec_implementation = {
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
