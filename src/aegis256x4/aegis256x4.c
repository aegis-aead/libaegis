#include <stddef.h>
#include <stdint.h>

#include "../common/common.h"
#include "../common/cpu.h"
#include "aegis256x4.h"
#include "aegis256x4_aesni.h"
#include "aegis256x4_altivec.h"
#include "aegis256x4_neon_aes.h"
#include "aegis256x4_avx2.h"
#include "aegis256x4_avx512.h"

#ifndef HAS_HW_AES
#    include "aegis256x4_soft.h"
static const aegis256x4_implementation *implementation = &aegis256x4_soft_implementation;
#else
#    if defined(__aarch64__) || defined(_M_ARM64)
static const aegis256x4_implementation *implementation = &aegis256x4_neon_aes_implementation;
#    elif defined(__x86_64__) || defined(__i386__)
static const aegis256x4_implementation *implementation = &aegis256x4_aesni_implementation;
#    elif defined(__ALTIVEC__) && defined(__CRYPTO__)
static const aegis256x4_implementation *implementation = &aegis256x4_altivec_implementation;
#    else
#        error "Unsupported architecture"
#    endif
#endif

size_t
aegis256x4_keybytes(void)
{
    return aegis256x4_KEYBYTES;
}

size_t
aegis256x4_npubbytes(void)
{
    return aegis256x4_NPUBBYTES;
}

size_t
aegis256x4_abytes_min(void)
{
    return aegis256x4_ABYTES_MIN;
}

size_t
aegis256x4_abytes_max(void)
{
    return aegis256x4_ABYTES_MAX;
}

size_t
aegis256x4_tailbytes_max(void)
{
    return aegis256x4_TAILBYTES_MAX;
}

int
aegis256x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                            const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->encrypt_detached(c, mac, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis256x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                            size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                            const uint8_t *k)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->decrypt_detached(m, c, clen, mac, maclen, ad, adlen, npub, k);
}

int
aegis256x4_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                   size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    return aegis256x4_encrypt_detached(c, c + mlen, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis256x4_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                   size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    int ret = -1;

    if (clen >= maclen) {
        ret = aegis256x4_decrypt_detached(m, c, clen - maclen, c + clen - maclen, maclen, ad, adlen,
                                          npub, k);
    }
    return ret;
}

void
aegis256x4_state_init(aegis256x4_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                      const uint8_t *k)
{
    memset(st_, 0, sizeof *st_);
    implementation->state_init(st_, ad, adlen, npub, k);
}

int
aegis256x4_state_encrypt_update(aegis256x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                                const uint8_t *m, size_t mlen)
{
    return implementation->state_encrypt_update(st_, c, clen_max, written, m, mlen);
}

int
aegis256x4_state_encrypt_detached_final(aegis256x4_state *st_, uint8_t *c, size_t clen_max,
                                        size_t *written, uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_encrypt_detached_final(st_, c, clen_max, written, mac, maclen);
}

int
aegis256x4_state_encrypt_final(aegis256x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                               size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_encrypt_final(st_, c, clen_max, written, maclen);
}

int
aegis256x4_state_decrypt_detached_update(aegis256x4_state *st_, uint8_t *m, size_t mlen_max,
                                         size_t *written, const uint8_t *c, size_t clen)
{
    return implementation->state_decrypt_detached_update(st_, m, mlen_max, written, c, clen);
}

int
aegis256x4_state_decrypt_detached_final(aegis256x4_state *st_, uint8_t *m, size_t mlen_max,
                                        size_t *written, const uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_decrypt_detached_final(st_, m, mlen_max, written, mac, maclen);
}

void
aegis256x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k)
{
    implementation->stream(out, len, npub, k);
}

void
aegis256x4_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                                   const uint8_t *k)
{
    implementation->encrypt_unauthenticated(c, m, mlen, npub, k);
}

void
aegis256x4_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                                   const uint8_t *k)
{
    implementation->decrypt_unauthenticated(m, c, clen, npub, k);
}

void
aegis256x4_mac_init(aegis256x4_mac_state *st_, const uint8_t *k, const uint8_t *npub)
{
    implementation->state_mac_init(st_, npub, k);
}

int
aegis256x4_mac_update(aegis256x4_mac_state *st_, const uint8_t *m, size_t mlen)
{
    return implementation->state_mac_update(st_, m, mlen);
}

int
aegis256x4_mac_final(aegis256x4_mac_state *st_, uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_mac_final(st_, mac, maclen);
}

int
aegis256x4_mac_verify(aegis256x4_mac_state *st_, const uint8_t *mac, size_t maclen)
{
    uint8_t expected_mac[32];

    switch (maclen) {
    case 16:
        implementation->state_mac_final(st_, expected_mac, maclen);
        return aegis_verify_16(expected_mac, mac);
    case 32:
        implementation->state_mac_final(st_, expected_mac, maclen);
        return aegis_verify_32(expected_mac, mac);
    default:
        errno = EINVAL;
        return -1;
    }
}

void
aegis256x4_mac_reset(aegis256x4_mac_state *st_)
{
    implementation->state_mac_reset(st_);
}

void
aegis256x4_mac_state_clone(aegis256x4_mac_state *dst, const aegis256x4_mac_state *src)
{
    implementation->state_mac_clone(dst, src);
}

int
aegis256x4_pick_best_implementation(void)
{
#ifndef HAS_HW_AES
    implementation = &aegis256x4_soft_implementation;
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
    if (aegis_runtime_has_neon_aes()) {
        implementation = &aegis256x4_neon_aes_implementation;
        return 0;
    }
#endif

#if defined(__x86_64__) || defined(_M_AMD64) || defined(__i386__) || defined(_M_IX86)
#    ifdef HAVE_VAESINTRIN_H
    if (aegis_runtime_has_vaes() && aegis_runtime_has_avx512f()) {
        implementation = &aegis256x4_avx512_implementation;
        return 0;
    }
    if (aegis_runtime_has_vaes() && aegis_runtime_has_avx2()) {
        implementation = &aegis256x4_avx2_implementation;
        return 0;
    }
#    endif
    if (aegis_runtime_has_aesni() && aegis_runtime_has_avx()) {
        implementation = &aegis256x4_aesni_implementation;
        return 0;
    }
#endif

#if defined(__ALTIVEC__) && defined(__CRYPTO__)
    if (aegis_runtime_has_altivec()) {
        implementation = &aegis256x4_altivec_implementation;
        return 0;
    }
#endif

    return 0; /* LCOV_EXCL_LINE */
}
