#ifndef softaes_H
#define softaes_H

#include <stdint.h>

#include "common.h"

/* Namespacing to avoid conflicts with libsodium */
#define softaes_blocks_encrypt_x8 libaegis_softaes_blocks_encrypt_x8
#define softaes_blocks_encrypt_x6 libaegis_softaes_blocks_encrypt_x6

typedef struct SoftAesBlock {
    uint32_t w0;
    uint32_t w1;
    uint32_t w2;
    uint32_t w3;
} SoftAesBlock;

/* Compute out[i] = AESRound(in[i]) ^ rk[i] for all blocks of an AEGIS state update at once.
 * out may alias rk, but in must not overlap with out. */
void softaes_blocks_encrypt_x8(SoftAesBlock out[8], const SoftAesBlock in[8],
                               const SoftAesBlock rk[8]);

void softaes_blocks_encrypt_x6(SoftAesBlock out[6], const SoftAesBlock in[6],
                               const SoftAesBlock rk[6]);

static inline SoftAesBlock
softaes_block_load(const uint8_t in[16])
{
#ifdef NATIVE_LITTLE_ENDIAN
    SoftAesBlock out;
    memcpy(&out, in, 16);
#else
    const SoftAesBlock out = { LOAD32_LE(in + 0), LOAD32_LE(in + 4), LOAD32_LE(in + 8),
                               LOAD32_LE(in + 12) };
#endif
    return out;
}

static inline SoftAesBlock
softaes_block_load64x2(const uint64_t a, const uint64_t b)
{
    const SoftAesBlock out = { (uint32_t) b, (uint32_t) (b >> 32), (uint32_t) a,
                               (uint32_t) (a >> 32) };
    return out;
}

static inline void
softaes_block_store(uint8_t out[16], const SoftAesBlock in)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(out, &in, 16);
#else
    STORE32_LE(out + 0, in.w0);
    STORE32_LE(out + 4, in.w1);
    STORE32_LE(out + 8, in.w2);
    STORE32_LE(out + 12, in.w3);
#endif
}

static inline SoftAesBlock
softaes_block_xor(const SoftAesBlock a, const SoftAesBlock b)
{
    const SoftAesBlock out = { a.w0 ^ b.w0, a.w1 ^ b.w1, a.w2 ^ b.w2, a.w3 ^ b.w3 };
    return out;
}

static inline SoftAesBlock
softaes_block_and(const SoftAesBlock a, const SoftAesBlock b)
{
    const SoftAesBlock out = { a.w0 & b.w0, a.w1 & b.w1, a.w2 & b.w2, a.w3 & b.w3 };
    return out;
}

#endif
