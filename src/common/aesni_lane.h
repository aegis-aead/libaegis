/*
 * Lane groups for the AES-NI backends, see aegis_lanes.h.
 * AEGIS_AESNI_LANES is the number of 16-byte lanes per group.
 */

#if AEGIS_AESNI_LANES == 1

typedef __m128i aes_lane_t;

#    define AES_LANE_LENGTH 16

#    define AES_LANE_LOAD(A)         _mm_loadu_si128((const __m128i *) (const void *) (A))
#    define AES_LANE_STORE(A, B)     _mm_storeu_si128((__m128i *) (void *) (A), (B))
#    define AES_LANE_XOR(A, B)       _mm_xor_si128((A), (B))
#    define AES_LANE_AND(A, B)       _mm_and_si128((A), (B))
#    define AES_LANE_ENC(A, B)       _mm_aesenc_si128((A), (B))
#    define AES_LANE_ZERO()          _mm_setzero_si128()
#    define AES_LANE_LOAD_64x2(A, B) (AES_BLOCK_LOAD_64x2((A), (B)).b0)

#elif AEGIS_AESNI_LANES == 2

typedef struct {
    __m128i b0;
    __m128i b1;
} aes_lane_t;

#    define AES_LANE_LENGTH 32

static inline aes_lane_t
AES_LANE_LOAD(const uint8_t *a)
{
    return (aes_lane_t) { _mm_loadu_si128((const __m128i *) (const void *) a),
                          _mm_loadu_si128((const __m128i *) (const void *) (a + 16)) };
}

static inline void
AES_LANE_STORE(uint8_t *a, const aes_lane_t b)
{
    _mm_storeu_si128((__m128i *) (void *) a, b.b0);
    _mm_storeu_si128((__m128i *) (void *) (a + 16), b.b1);
}

static inline aes_lane_t
AES_LANE_XOR(const aes_lane_t a, const aes_lane_t b)
{
    return (aes_lane_t) { _mm_xor_si128(a.b0, b.b0), _mm_xor_si128(a.b1, b.b1) };
}

static inline aes_lane_t
AES_LANE_AND(const aes_lane_t a, const aes_lane_t b)
{
    return (aes_lane_t) { _mm_and_si128(a.b0, b.b0), _mm_and_si128(a.b1, b.b1) };
}

static inline aes_lane_t
AES_LANE_ENC(const aes_lane_t a, const aes_lane_t b)
{
    return (aes_lane_t) { _mm_aesenc_si128(a.b0, b.b0), _mm_aesenc_si128(a.b1, b.b1) };
}

static inline aes_lane_t
AES_LANE_ZERO(void)
{
    return (aes_lane_t) { _mm_setzero_si128(), _mm_setzero_si128() };
}

static inline aes_lane_t
AES_LANE_LOAD_64x2(uint64_t a, uint64_t b)
{
    const aes_block_t t = AES_BLOCK_LOAD_64x2(a, b);

    return (aes_lane_t) { t.b0, t.b1 };
}

#else
#    error "AEGIS_AESNI_LANES must be 1 or 2"
#endif
