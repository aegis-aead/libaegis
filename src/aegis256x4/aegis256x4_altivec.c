#if defined(__ALTIVEC__) && defined(__CRYPTO__)

#    include <errno.h>
#    include <stddef.h>
#    include <stdint.h>
#    include <stdlib.h>
#    include <string.h>

#    include "../common/common.h"
#    include "aegis256x4.h"
#    include "aegis256x4_altivec.h"

#    include <altivec.h>

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("altivec,crypto"))), apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("+altivec+crypto")
#    endif

#    define AES_BLOCK_LENGTH 64

typedef struct {
    vector unsigned char b0;
    vector unsigned char b1;
    vector unsigned char b2;
    vector unsigned char b3;
} aes_block_t;

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vec_xor(a.b0, b.b0), vec_xor(a.b1, b.b1), vec_xor(a.b2, b.b2),
                           vec_xor(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vec_and(a.b0, b.b0), vec_and(a.b1, b.b1), vec_and(a.b2, b.b2),
                           vec_and(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { vec_xl_be(0, a), vec_xl_be(0, a + 16), vec_xl_be(0, a + 32),
                           vec_xl_be(0, a + 48) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const vector unsigned char t =
        vec_revb(vec_insert(a, vec_promote((unsigned long long) (b), 1), 0));
    return (aes_block_t) { t, t, t, t };
}
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    vec_xst_be(b.b0, 0, a);
    vec_xst_be(b.b1, 0, a + 16);
    vec_xst_be(b.b2, 0, a + 32);
    vec_xst_be(b.b3, 0, a + 48);
}

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vec_cipher_be(a.b0, b.b0), vec_cipher_be(a.b1, b.b1),
                           vec_cipher_be(a.b2, b.b2), vec_cipher_be(a.b3, b.b3) };
}

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

#    include "aegis256x4_common.h"

struct aegis256x4_implementation aegis256x4_altivec_implementation = {
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

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#endif
