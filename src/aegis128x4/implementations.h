#ifndef aegis128x4_implementations_H
#define aegis128x4_implementations_H

#include <stddef.h>
#include <stdint.h>

#include "aegis128x4.h"

typedef struct aegis128x4_implementation {
    int (*encrypt_detached)(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                            const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k);
    int (*decrypt_detached)(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                            size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                            const uint8_t *k);
    void (*randombytes_deterministic)(uint8_t *out, size_t len, const uint8_t *npub,
                                      const uint8_t *k);
    void (*encrypt_unauthenticated)(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                                    const uint8_t *k);
    void (*decrypt_unauthenticated)(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                                    const uint8_t *k);
    void (*state_init)(aegis128x4_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                       const uint8_t *k);
    int (*state_encrypt_update)(aegis128x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                                const uint8_t *m, size_t mlen);
    int (*state_encrypt_detached_final)(aegis128x4_state *st_, uint8_t *c, size_t clen_max,
                                        size_t *written, uint8_t *mac, size_t maclen);
    int (*state_encrypt_final)(aegis128x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                               size_t maclen);
    int (*state_decrypt_detached_update)(aegis128x4_state *st_, uint8_t *m, size_t mlen_max,
                                         size_t *written, const uint8_t *c, size_t clen);
    int (*state_decrypt_detached_final)(aegis128x4_state *st_, uint8_t *m, size_t mlen_max,
                                        size_t *written, const uint8_t *mac, size_t maclen);
} aegis128x4_implementation;

#endif
