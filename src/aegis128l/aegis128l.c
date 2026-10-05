#include <stddef.h>
#include <stdint.h>

#include "../common/common.h"
#include "../common/cpu.h"
#include "aegis128l.h"
#include "aegis128l_aesni.h"
#include "aegis128l_altivec.h"
#include "aegis128l_neon_aes.h"
#include "aegis128l_neon_sha3.h"

#ifndef HAS_HW_AES
#    include "aegis128l_soft.h"
static const aegis128l_implementation *implementation = &aegis128l_soft_implementation;
#else
#    if defined(__aarch64__) || defined(_M_ARM64)
static const aegis128l_implementation *implementation = &aegis128l_neon_aes_implementation;
#    elif defined(__x86_64__) || defined(__i386__)
static const aegis128l_implementation *implementation = &aegis128l_aesni_implementation;
#    elif defined(__ALTIVEC__) && defined(__CRYPTO__)
static const aegis128l_implementation *implementation = &aegis128l_altivec_implementation;
#    else
#        error "Unsupported architecture"
#    endif
#endif

size_t
aegis128l_keybytes(void)
{
    return aegis128l_KEYBYTES;
}

size_t
aegis128l_npubbytes(void)
{
    return aegis128l_NPUBBYTES;
}

size_t
aegis128l_abytes_min(void)
{
    return aegis128l_ABYTES_MIN;
}

size_t
aegis128l_abytes_max(void)
{
    return aegis128l_ABYTES_MAX;
}

size_t
aegis128l_tailbytes_max(void)
{
    return aegis128l_TAILBYTES_MAX;
}

int
aegis128l_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->encrypt_detached(c, mac, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis128l_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
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
aegis128l_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                  size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    return aegis128l_encrypt_detached(c, c + mlen, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis128l_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                  size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    int ret = -1;

    if (clen >= maclen) {
        ret = aegis128l_decrypt_detached(m, c, clen - maclen, c + clen - maclen, maclen, ad, adlen,
                                         npub, k);
    }
    return ret;
}

void
aegis128l_state_init(aegis128l_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                     const uint8_t *k)
{
    memset(st_, 0, sizeof *st_);
    implementation->state_init(st_, ad, adlen, npub, k);
}

int
aegis128l_state_encrypt_update(aegis128l_state *st_, uint8_t *c, const uint8_t *m, size_t mlen)
{
    return implementation->state_encrypt_update(st_, c, m, mlen);
}

int
aegis128l_state_encrypt_final(aegis128l_state *st_, uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_encrypt_final(st_, mac, maclen);
}

int
aegis128l_state_decrypt_update(aegis128l_state *st_, uint8_t *m, const uint8_t *c, size_t clen)
{
    return implementation->state_decrypt_update(st_, m, c, clen);
}

int
aegis128l_state_decrypt_final(aegis128l_state *st_, const uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_decrypt_final(st_, mac, maclen);
}

void
aegis128l_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k)
{
    implementation->stream(out, len, npub, k);
}

void
aegis128l_stream_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *npub,
                     const uint8_t *k)
{
    implementation->stream_xor(out, in, len, npub, k);
}

void
aegis128l_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                                  const uint8_t *k)
{
    implementation->encrypt_unauthenticated(c, m, mlen, npub, k);
}

void
aegis128l_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                                  const uint8_t *k)
{
    implementation->decrypt_unauthenticated(m, c, clen, npub, k);
}

void
aegis128l_mac_init(aegis128l_mac_state *st_, const uint8_t *k, const uint8_t *npub)
{
    memset(st_, 0, sizeof *st_);
    implementation->state_mac_init(st_, npub, k);
}

int
aegis128l_mac_update(aegis128l_mac_state *st_, const uint8_t *m, size_t mlen)
{
    return implementation->state_mac_update(st_, m, mlen);
}

int
aegis128l_mac_final(aegis128l_mac_state *st_, uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        errno = EINVAL;
        return -1;
    }
    return implementation->state_mac_final(st_, mac, maclen);
}

int
aegis128l_mac_verify(aegis128l_mac_state *st_, const uint8_t *mac, size_t maclen)
{
    uint8_t expected_mac[32];
    int     ret;

    switch (maclen) {
    case 16:
        implementation->state_mac_final(st_, expected_mac, maclen);
        ret = aegis_verify_16(expected_mac, mac);
        break;
    case 32:
        implementation->state_mac_final(st_, expected_mac, maclen);
        ret = aegis_verify_32(expected_mac, mac);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    // Both the match and the mismatch path reach this point; the mismatch path is the one an
    // attacker can drive repeatedly.
    aegis_secure_zero(expected_mac, sizeof expected_mac);

    return ret;
}

void
aegis128l_mac_reset(aegis128l_mac_state *st_)
{
    implementation->state_mac_reset(st_);
}

void
aegis128l_mac_state_clone(aegis128l_mac_state *dst, const aegis128l_mac_state *src)
{
    implementation->state_mac_clone(dst, src);
}

int
aegis128l_pick_best_implementation(void)
{
#ifndef HAS_HW_AES
    implementation = &aegis128l_soft_implementation;
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
    if (aegis_runtime_has_neon_sha3()) {
        implementation = &aegis128l_neon_sha3_implementation;
        return 0;
    }
    if (aegis_runtime_has_neon_aes()) {
        implementation = &aegis128l_neon_aes_implementation;
        return 0;
    }
#endif

#if defined(__x86_64__) || defined(_M_AMD64) || defined(__i386__) || defined(_M_IX86)
    if (aegis_runtime_has_aesni() && aegis_runtime_has_avx()) {
        implementation = &aegis128l_aesni_implementation;
        return 0;
    }
#endif

#if defined(__ALTIVEC__) && defined(__CRYPTO__)
    if (aegis_runtime_has_altivec()) {
        implementation = &aegis128l_altivec_implementation;
        return 0;
    }
#endif

    return 0; /* LCOV_EXCL_LINE */
}
