/*
 * NEON lanes for aegis_lanes.h.
 * A group is two 16-byte lanes, so that its state and the message fit in the 32 vector registers.
 */

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
} aes_lane_t;

#define AES_LANE_LENGTH 32

/* Each group goes through the whole input, since chunk sizes were only tuned on x86. */
#define AEGIS_LANES_CHUNK AEGIS_LANES_WHOLE

/* Without this, the bulk loop speed depends on where the linker happens to put it. */
#define AES_LANE_LOOP_ALIGN CRYPTO_ALIGN_LOOP(64)

static inline aes_lane_t
AES_LANE_LOAD(const uint8_t *a)
{
    return (aes_lane_t) { vld1q_u8(a), vld1q_u8(a + 16) };
}

static inline void
AES_LANE_STORE(uint8_t *a, const aes_lane_t b)
{
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
}

static inline aes_lane_t
AES_LANE_XOR(const aes_lane_t a, const aes_lane_t b)
{
    return (aes_lane_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1) };
}

static inline aes_lane_t
AES_LANE_AND(const aes_lane_t a, const aes_lane_t b)
{
    return (aes_lane_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1) };
}

static inline aes_lane_t
AES_LANE_ENC(const aes_lane_t a, const aes_lane_t b)
{
    return (aes_lane_t) { veorq_u8(vaesmcq_u8(vaeseq_u8(a.b0, vmovq_n_u8(0))), b.b0),
                          veorq_u8(vaesmcq_u8(vaeseq_u8(a.b1, vmovq_n_u8(0))), b.b1) };
}

static inline aes_lane_t
AES_LANE_ZERO(void)
{
    return (aes_lane_t) { vmovq_n_u8(0), vmovq_n_u8(0) };
}

static inline aes_lane_t
AES_LANE_LOAD_64x2(uint64_t a, uint64_t b)
{
    const aes_block_t t = AES_BLOCK_LOAD_64x2(a, b);

    return (aes_lane_t) { t.b0, t.b0 };
}

static inline aes_lane_t
aes_lane_broadcast128(const uint8_t *a)
{
    const uint8x16_t t = vld1q_u8(a);

    return (aes_lane_t) { t, t };
}
#define AES_LANE_BROADCAST128(A) aes_lane_broadcast128(A)

#ifdef __ARM_FEATURE_SHA3

#    define AES_LANE_SHA3

static inline aes_lane_t
AES_LANE_XOR3(const aes_lane_t a, const aes_lane_t b, const aes_lane_t c)
{
    return (aes_lane_t) { veor3q_u8(a.b0, b.b0, c.b0), veor3q_u8(a.b1, b.b1, c.b1) };
}

/* a ^ (b & ~c) */
static inline aes_lane_t
AES_LANE_BCAX(const aes_lane_t a, const aes_lane_t b, const aes_lane_t c)
{
    return (aes_lane_t) { vbcaxq_u8(a.b0, b.b0, c.b0), vbcaxq_u8(a.b1, b.b1, c.b1) };
}

static inline aes_lane_t
AES_LANE_NOT(const aes_lane_t a)
{
    return (aes_lane_t) { vmvnq_u8(a.b0), vmvnq_u8(a.b1) };
}

static inline aes_lane_t
AES_LANE_ENC0(const aes_lane_t a)
{
    return (aes_lane_t) { vaesmcq_u8(vaeseq_u8(a.b0, vmovq_n_u8(0))),
                          vaesmcq_u8(vaeseq_u8(a.b1, vmovq_n_u8(0))) };
}

/* Encrypts ~a: the all-ones key undoes the inversion. */
static inline aes_lane_t
AES_LANE_ENC0_NOT(const aes_lane_t a)
{
    return (aes_lane_t) { vaesmcq_u8(vaeseq_u8(a.b0, vmovq_n_u8(0xff))),
                          vaesmcq_u8(vaeseq_u8(a.b1, vmovq_n_u8(0xff))) };
}

#endif
