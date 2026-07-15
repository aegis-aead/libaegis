#include <stddef.h>
#include <stdint.h>

#include "../common/common.h"
#include "../common/cpu.h"

#ifndef HAS_HW_AES

#    include "../common/softaes.h"
#    include "aegis256x4.h"
#    include "aegis256x4_soft.h"

#    define AES_BLOCK_LENGTH 64

typedef struct {
    SoftAesBlock b0;
    SoftAesBlock b1;
    SoftAesBlock b2;
    SoftAesBlock b3;
} aes_block_t;

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { softaes_block_xor(a.b0, b.b0), softaes_block_xor(a.b1, b.b1),
                           softaes_block_xor(a.b2, b.b2), softaes_block_xor(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { softaes_block_and(a.b0, b.b0), softaes_block_and(a.b1, b.b1),
                           softaes_block_and(a.b2, b.b2), softaes_block_and(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { softaes_block_load(a), softaes_block_load(a + 16),
                           softaes_block_load(a + 32), softaes_block_load(a + 48) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const SoftAesBlock t = softaes_block_load64x2(a, b);
    return (aes_block_t) { t, t, t, t };
}
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    softaes_block_store(a, b.b0);
    softaes_block_store(a + 16, b.b1);
    softaes_block_store(a + 32, b.b2);
    softaes_block_store(a + 48, b.b3);
}

static inline void
aegis256x4_update(aes_block_t *const state, const aes_block_t d)
{
    COMPILER_ASSERT(sizeof(aes_block_t) == 4 * sizeof(SoftAesBlock));
    softaes_aegis_rotate6_x4((SoftAesBlock *) (void *) state);

    state[0] = AES_BLOCK_XOR(state[0], d);
}

#    include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_soft_implementation = {
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
