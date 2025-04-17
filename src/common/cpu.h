#ifndef cpu_H
#define cpu_H

#if defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_FEATURE_AES) && defined(__ARM_NEON)
#    define HAS_HW_AES
#elif defined(__AES__) && defined(__AVX__)
#    define HAS_HW_AES
#elif defined(__ALTIVEC__) && defined(__CRYPTO__)
#    define HAS_HW_AES
#endif

int aegis_runtime_get_cpu_features(void);

int aegis_runtime_has_neon(void);

int aegis_runtime_has_neon_aes(void);

int aegis_runtime_has_avx(void);

int aegis_runtime_has_avx2(void);

int aegis_runtime_has_avx512f(void);

int aegis_runtime_has_aesni(void);

int aegis_runtime_has_vaes(void);

int aegis_runtime_has_altivec(void);

#endif
