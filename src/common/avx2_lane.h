/*
 * Lane groups for the AVX2 backends, see aegis_lanes.h.
 * AEGIS_AVX2_LANES is the number of 256-bit registers per state word in a group.
 */

#ifndef AEGIS_AVX2_LANES
#    define AEGIS_AVX2_LANES 1
#endif

#if AEGIS_AVX2_LANES == 1

typedef __m256i aes_lane_t;

#    define AES_LANE_LENGTH 32

#    define AES_LANE_LOAD(A)         _mm256_loadu_si256((const __m256i *) (const void *) (A))
#    define AES_LANE_STORE(A, B)     _mm256_storeu_si256((__m256i *) (void *) (A), (B))
#    define AES_LANE_XOR(A, B)       _mm256_xor_si256((A), (B))
#    define AES_LANE_AND(A, B)       _mm256_and_si256((A), (B))
#    define AES_LANE_ENC(A, B)       _mm256_aesenc_epi128((A), (B))
#    define AES_LANE_ZERO()          _mm256_setzero_si256()
#    define AES_LANE_LOAD_64x2(A, B) (AES_BLOCK_LOAD_64x2((A), (B)).b0)
#    define AES_LANE_BROADCAST128(A) (AES_BLOCK_BROADCAST128(A).b0)

#elif AEGIS_AVX2_LANES == 2

typedef aes_block_t aes_lane_t;

#    define AES_LANE_LENGTH      AES_BLOCK_LENGTH
#    define AES_LANE_LOAD(A)     AES_BLOCK_LOAD(A)
#    define AES_LANE_STORE(A, B) AES_BLOCK_STORE((A), (B))
#    define AES_LANE_XOR(A, B)   AES_BLOCK_XOR((A), (B))
#    define AES_LANE_AND(A, B)   AES_BLOCK_AND((A), (B))
#    define AES_LANE_ENC(A, B)   AES_ENC((A), (B))
#    define AES_LANE_ZERO()      ((aes_block_t) { _mm256_setzero_si256(), _mm256_setzero_si256() })

#else
#    error "AEGIS_AVX2_LANES must be 1 or 2"
#endif
