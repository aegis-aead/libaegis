#include <stddef.h>
#include <stdint.h>

#include "../common/common.h"
#include "../common/cpu.h"

#ifndef HAS_HW_AES

#    include "../common/softaes.h"
#    include "aegis128l.h"
#    include "aegis128l_soft.h"

#    define AES_BLOCK_LENGTH 16

typedef SoftAesBlock aes_block_t;

#    define AES_BLOCK_XOR(A, B)       softaes_block_xor((A), (B))
#    define AES_BLOCK_AND(A, B)       softaes_block_and((A), (B))
#    define AES_BLOCK_LOAD(A)         softaes_block_load(A)
#    define AES_BLOCK_LOAD_64x2(A, B) softaes_block_load64x2((A), (B))
#    define AES_BLOCK_STORE(A, B)     softaes_block_store((A), (B))

static inline void
aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t in[8];
    size_t      i;

    for (i = 0; i < 8; i++) {
        in[i] = state[(i + 7) % 8];
    }
    softaes_blocks_encrypt_x8(state, in, state);

    state[0] = AES_BLOCK_XOR(state[0], d1);
    state[4] = AES_BLOCK_XOR(state[4], d2);
}

#    include "aegis128l_common.h"

struct aegis128l_implementation aegis128l_soft_implementation = {
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

#endif
