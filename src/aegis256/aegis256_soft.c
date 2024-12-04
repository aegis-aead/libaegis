#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../common/common.h"
#include "../common/cpu.h"

#ifndef HAS_HW_AES

#    include "../common/softaes.h"
#    include "aegis256.h"
#    include "aegis256_soft.h"

#    define AES_BLOCK_LENGTH 16

typedef SoftAesBlock aes_block_t;

#    define AES_BLOCK_XOR(A, B)       softaes_block_xor((A), (B))
#    define AES_BLOCK_AND(A, B)       softaes_block_and((A), (B))
#    define AES_BLOCK_LOAD(A)         softaes_block_load(A)
#    define AES_BLOCK_LOAD_64x2(A, B) softaes_block_load64x2((A), (B))
#    define AES_BLOCK_STORE(A, B)     softaes_block_store((A), (B))
#    define AES_ENC(A, B)             softaes_block_encrypt((A), (B))

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

#    include "aegis256_common.h"

struct aegis256_implementation aegis256_soft_implementation = {
    .encrypt_detached              = encrypt_detached,
    .decrypt_detached              = decrypt_detached,
    .encrypt_unauthenticated       = encrypt_unauthenticated,
    .decrypt_unauthenticated       = decrypt_unauthenticated,
    .stream                        = stream,
    .state_init                    = state_init,
    .state_encrypt_update          = state_encrypt_update,
    .state_encrypt_detached_final  = state_encrypt_detached_final,
    .state_encrypt_final           = state_encrypt_final,
    .state_decrypt_detached_update = state_decrypt_detached_update,
    .state_decrypt_detached_final  = state_decrypt_detached_final,
    .state_mac_init                = state_mac_init,
    .state_mac_update              = state_mac_update,
    .state_mac_final               = state_mac_final,
    .state_mac_reset               = state_mac_reset,
    .state_mac_clone               = state_mac_clone,
};

#endif
