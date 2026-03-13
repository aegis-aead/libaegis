#ifndef aegis256_implementations_H
#define aegis256_implementations_H

#include <stddef.h>
#include <stdint.h>

#include "aegis256.h"

/* Namespacing to avoid conflicts with libsodium */
#define aegis256_soft_implementation      libaegis_aegis256_soft_implementation
#define aegis256_aesni_implementation     libaegis_aegis256_aesni_implementation
#define aegis256_neon_aes_implementation  libaegis_aegis256_neon_aes_implementation
#define aegis256_neon_sha3_implementation libaegis_aegis256_neon_sha3_implementation
#define aegis256_altivec_implementation   libaegis_aegis256_altivec_implementation

typedef struct aegis256_implementation {
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
    void (*state_init)(aegis256_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                       const uint8_t *k);
    int (*state_encrypt_update)(aegis256_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
    int (*state_encrypt_final)(aegis256_state *st_, uint8_t *mac, size_t maclen);
    int (*state_decrypt_update)(aegis256_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
    int (*state_decrypt_final)(aegis256_state *st_, const uint8_t *mac, size_t maclen);
    void (*state_mac_init)(aegis256_mac_state *st_, const uint8_t *npub, const uint8_t *k);
    int (*state_mac_update)(aegis256_mac_state *st_, const uint8_t *ad, size_t adlen);
    int (*state_mac_final)(aegis256_mac_state *st_, uint8_t *mac, size_t maclen);
    void (*state_mac_reset)(aegis256_mac_state *st);
    void (*state_mac_clone)(aegis256_mac_state *dst, const aegis256_mac_state *src);
} aegis256_implementation;

#endif
