#ifndef aegis128x4_implementations_H
#define aegis128x4_implementations_H

#include <stddef.h>
#include <stdint.h>

#include "aegis128x4.h"

/* Namespacing to avoid conflicts with libsodium */
#define aegis128x4_soft_implementation      libaegis_aegis128x4_soft_implementation
#define aegis128x4_aesni_implementation     libaegis_aegis128x4_aesni_implementation
#define aegis128x4_neon_aes_implementation  libaegis_aegis128x4_neon_aes_implementation
#define aegis128x4_neon_sha3_implementation libaegis_aegis128x4_neon_sha3_implementation
#define aegis128x4_altivec_implementation   libaegis_aegis128x4_altivec_implementation
#define aegis128x4_avx2_implementation      libaegis_aegis128x4_avx2_implementation
#define aegis128x4_avx512_implementation    libaegis_aegis128x4_avx512_implementation

typedef struct aegis128x4_implementation {
    int (*encrypt_detached)(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                            const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k);
    int (*decrypt_detached)(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                            size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                            const uint8_t *k);
    void (*stream)(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void (*encrypt_unauthenticated)(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                                    const uint8_t *k);
    void (*decrypt_unauthenticated)(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                                    const uint8_t *k);
    void (*state_init)(aegis128x4_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                       const uint8_t *k);
    int (*state_encrypt_update)(aegis128x4_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
    int (*state_encrypt_final)(aegis128x4_state *st_, uint8_t *mac, size_t maclen);
    int (*state_decrypt_update)(aegis128x4_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
    int (*state_decrypt_final)(aegis128x4_state *st_, const uint8_t *mac, size_t maclen);
    void (*state_mac_init)(aegis128x4_mac_state *st_, const uint8_t *npub, const uint8_t *k);
    int (*state_mac_update)(aegis128x4_mac_state *st_, const uint8_t *ad, size_t adlen);
    int (*state_mac_final)(aegis128x4_mac_state *st_, uint8_t *mac, size_t maclen);
    void (*state_mac_reset)(aegis128x4_mac_state *st);
    void (*state_mac_clone)(aegis128x4_mac_state *dst, const aegis128x4_mac_state *src);
} aegis128x4_implementation;

#endif
