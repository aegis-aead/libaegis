#define RATE      16
#define ALIGNMENT 16

// If not inverting state[3], treat bitwise-NOT operations as no-ops.
#ifndef AES_INVERT_STATE3
#    define AES_BLOCK_NOT(A) (A)
#    define AES_BLOCK_XNOR(A, B) AES_BLOCK_XOR((A), (B))
#endif

typedef aes_block_t aegis_blocks[6];

static inline void
aegis256_init(const uint8_t *key, const uint8_t *nonce, aes_block_t *const state)
{
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH)
        const uint8_t c0_[AES_BLOCK_LENGTH] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                                                0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH)
        const uint8_t c1_[AES_BLOCK_LENGTH] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
                                                0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };

    const aes_block_t c0    = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1    = AES_BLOCK_LOAD(c1_);
    const aes_block_t k0    = AES_BLOCK_LOAD(key);
    const aes_block_t k1    = AES_BLOCK_LOAD(key + AES_BLOCK_LENGTH);
    const aes_block_t n0    = AES_BLOCK_LOAD(nonce);
    const aes_block_t n1    = AES_BLOCK_LOAD(nonce + AES_BLOCK_LENGTH);
    const aes_block_t k0_n0 = AES_BLOCK_XOR(k0, n0);
    const aes_block_t k1_n1 = AES_BLOCK_XOR(k1, n1);
    int               i;

    state[0] = k0_n0;
    state[1] = k1_n1;
    state[2] = c1;
    state[3] = AES_BLOCK_NOT(c0);
    state[4] = AES_BLOCK_XOR(k0, c0);
    state[5] = AES_BLOCK_XOR(k1, c1);
    for (i = 0; i < 4; i++) {
        aegis256_update(state, k0);
        aegis256_update(state, k1);
        aegis256_update(state, k0_n0);
        aegis256_update(state, k1_n1);
    }
}

static inline void
aegis256_mac(uint8_t *mac, size_t maclen, uint64_t adlen, uint64_t mlen, aes_block_t *const state)
{
    aes_block_t tmp;
    int         i;

    tmp = AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AES_BLOCK_XNOR(tmp, state[3]);

    for (i = 0; i < 7; i++) {
        aegis256_update(state, tmp);
    }

    if (maclen == 16) {
        tmp = AES_BLOCK_XOR(state[5], state[4]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XNOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac, tmp);
    } else if (maclen == 32) {
        tmp = AES_BLOCK_XOR(AES_BLOCK_XOR(state[2], state[1]), state[0]);
        AES_BLOCK_STORE(mac, tmp);
        tmp = AES_BLOCK_XNOR(AES_BLOCK_XOR(state[5], state[4]), state[3]);
        AES_BLOCK_STORE(mac + 16, tmp);
    } else {
        memset(mac, 0, maclen);
    }
}

static inline void
aegis256_absorb(const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;

    msg = AES_BLOCK_LOAD(src);
    aegis256_update(state, msg);
}

static inline void
aegis256_absorb_rate(const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;

    msg = AES_BLOCK_LOAD(src);
    aegis256_update(state, msg);
}

static inline void
aegis256_squeeze_keystream(uint8_t *const dst, aes_block_t *const state)
{
    aes_block_t tmp;

    tmp = AES_BLOCK_XOR(state[5], state[4]);
    tmp = AES_BLOCK_XOR(tmp, state[1]);
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_AND(state[2], AES_BLOCK_NOT(state[3])));
    AES_BLOCK_STORE(dst, tmp);
}

static inline void
aegis256_enc(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;
    aes_block_t tmp;

    msg = AES_BLOCK_LOAD(src);
    tmp = AES_BLOCK_XOR(msg, state[5]);
    tmp = AES_BLOCK_XOR(tmp, state[4]);
    tmp = AES_BLOCK_XOR(tmp, state[1]);
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_AND(state[2], AES_BLOCK_NOT(state[3])));
    AES_BLOCK_STORE(dst, tmp);

    aegis256_update(state, msg);
}

static inline void
aegis256_dec(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;

    msg = AES_BLOCK_LOAD(src);
    msg = AES_BLOCK_XOR(msg, state[5]);
    msg = AES_BLOCK_XOR(msg, state[4]);
    msg = AES_BLOCK_XOR(msg, state[1]);
    msg = AES_BLOCK_XOR(msg, AES_BLOCK_AND(state[2], AES_BLOCK_NOT(state[3])));
    AES_BLOCK_STORE(dst, msg);

    aegis256_update(state, msg);
}

static inline void
aegis256_declast(uint8_t *const dst, const uint8_t *const src, size_t len, aes_block_t *const state)
{
    uint8_t     pad[RATE];
    aes_block_t msg;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    msg = AES_BLOCK_LOAD(pad);
    msg = AES_BLOCK_XOR(msg, state[5]);
    msg = AES_BLOCK_XOR(msg, state[4]);
    msg = AES_BLOCK_XOR(msg, state[1]);
    msg = AES_BLOCK_XOR(msg, AES_BLOCK_AND(state[2], AES_BLOCK_NOT(state[3])));
    AES_BLOCK_STORE(pad, msg);

    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);

    msg = AES_BLOCK_LOAD(pad);

    aegis256_update(state, msg);
}

static int
encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    aegis_blocks                    state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis256_absorb(src, state);
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis256_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }

    aegis256_mac(mac, maclen, adlen, mlen, state);

    return 0;
}

static int
decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac, size_t maclen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    aegis_blocks                    state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    CRYPTO_ALIGN(16) uint8_t        computed_mac[32];
    const size_t                    mlen = clen;
    size_t                          i;
    int                             ret;

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis256_absorb(src, state);
    }
    if (m != NULL) {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256_dec(dst, c + i, state);
        }
    }
    if (mlen % RATE) {
        if (m != NULL) {
            aegis256_declast(m + i, c + i, mlen % RATE, state);
        } else {
            aegis256_declast(dst, c + i, mlen % RATE, state);
        }
    }

    COMPILER_ASSERT(sizeof computed_mac >= 32);
    aegis256_mac(computed_mac, maclen, adlen, mlen, state);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }
    if (ret != 0 && m != NULL) {
        memset(m, 0, mlen);
    }
    return ret;
}

static void
stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k)
{
    aegis_blocks                    state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    memset(src, 0, sizeof src);
    if (npub == NULL) {
        npub = src;
    }

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= len; i += RATE) {
        aegis256_enc(out + i, src, state);
    }
    if (len % RATE) {
        aegis256_enc(dst, src, state);
        memcpy(out + i, dst, len % RATE);
    }
}

static void
encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen, const uint8_t *npub,
                        const uint8_t *k)
{
    aegis_blocks                    state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis256_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }
}

static void
decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *npub,
                        const uint8_t *k)
{
    aegis_blocks state;
    const size_t mlen = clen;
    size_t       i;

    aegis256_init(k, npub, state);

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256_dec(m + i, c + i, state);
    }
    if (mlen % RATE) {
        aegis256_declast(m + i, c + i, mlen % RATE, state);
    }
}

typedef struct _aegis256_state {
    aegis_blocks blocks;
    uint8_t      buf[RATE];
    uint64_t     adlen;
    uint64_t     mlen;
    size_t       pos;
} _aegis256_state;

typedef struct _aegis256_mac_state {
    aegis_blocks blocks;
    aegis_blocks blocks0;
    uint8_t      buf[RATE];
    uint64_t     adlen;
    size_t       pos;
} _aegis256_mac_state;

static void
state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
           const uint8_t *k)
{
    aegis_blocks           blocks;
    _aegis256_state *const st =
        (_aegis256_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                             ~(uintptr_t) (ALIGNMENT - 1));
    size_t i;

    COMPILER_ASSERT((sizeof *st) + ALIGNMENT <= sizeof *st_);
    st->mlen = 0;
    st->pos  = 0;

    aegis256_init(k, npub, blocks);
    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256_absorb(ad + i, blocks);
    }
    if (adlen % RATE) {
        memset(st->buf, 0, RATE);
        memcpy(st->buf, ad + i, adlen % RATE);
        aegis256_absorb(st->buf, blocks);
    }
    st->adlen = adlen;

    memset(st->buf, 0, sizeof st->buf);

    memcpy(st->blocks, blocks, sizeof blocks);
}

static int
state_encrypt_update(aegis256_state *st_, uint8_t *c, const uint8_t *m, size_t mlen)
{
    aegis_blocks           blocks;
    _aegis256_state *const st =
        (_aegis256_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                             ~(uintptr_t) (ALIGNMENT - 1));
    size_t i = 0;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    st->mlen += mlen;

    // Handle leftover keystream from previous call
    if (st->pos != 0) {
        const size_t available = RATE - st->pos;
        const size_t n         = mlen < available ? mlen : available;
        size_t       j;
        uint8_t      tmp;

        for (j = 0; j < n; j++) {
            tmp                  = m[j];
            c[j]                 = m[j] ^ st->buf[st->pos + j];
            st->buf[st->pos + j] = tmp;
        }
        st->pos += n;
        m += n;
        c += n;
        mlen -= n;

        if (st->pos < RATE) {
            // Still consuming keystream from previous call
            memcpy(st->blocks, blocks, sizeof blocks);
            return 0;
        }

        // Full block accumulated, update state
        aegis256_absorb_rate(st->buf, blocks);
        st->pos = 0;
    }

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256_enc(c + i, m + i, blocks);
    }

    left = mlen - i;
    if (left != 0) {
        size_t  j;
        uint8_t tmp;

        // Generate keystream without updating state
        aegis256_squeeze_keystream(st->buf, blocks);

        for (j = 0; j < left; j++) {
            tmp        = m[i + j];
            c[i + j]   = m[i + j] ^ st->buf[j];
            st->buf[j] = tmp;
        }
        st->pos = left;
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_encrypt_final(aegis256_state *st_, uint8_t *mac, size_t maclen)
{
    aegis_blocks           blocks;
    _aegis256_state *const st =
        (_aegis256_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                             ~(uintptr_t) (ALIGNMENT - 1));

    memcpy(blocks, st->blocks, sizeof blocks);

    // Ciphertext was already output during _update; absorb cached plaintext into state
    if (st->pos != 0) {
        CRYPTO_ALIGN(ALIGNMENT) uint8_t tmp[RATE];
        memset(tmp, 0, sizeof tmp);
        memcpy(tmp, st->buf, st->pos);
        aegis256_absorb_rate(tmp, blocks);
    }

    aegis256_mac(mac, maclen, st->adlen, st->mlen, blocks);

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_decrypt_update(aegis256_state *st_, uint8_t *m, const uint8_t *c, size_t clen)
{
    aegis_blocks           blocks;
    _aegis256_state *const st =
        (_aegis256_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                             ~(uintptr_t) (ALIGNMENT - 1));
    size_t i = 0;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    st->mlen += clen;

    // Handle leftover keystream from previous call
    if (st->pos != 0) {
        const size_t available = RATE - st->pos;
        const size_t n         = clen < available ? clen : available;
        size_t       j;

        for (j = 0; j < n; j++) {
            if (m != NULL) {
                m[j]                 = c[j] ^ st->buf[st->pos + j];
                st->buf[st->pos + j] = m[j];
            } else {
                uint8_t plaintext    = c[j] ^ st->buf[st->pos + j];
                st->buf[st->pos + j] = plaintext;
            }
        }
        st->pos += n;
        if (m != NULL) {
            m += n;
        }
        c += n;
        clen -= n;

        if (st->pos < RATE) {
            // Still consuming keystream
            memcpy(st->blocks, blocks, sizeof blocks);
            return 0;
        }

        // Full block accumulated, update state
        aegis256_absorb_rate(st->buf, blocks);
        st->pos = 0;
    }

    if (m != NULL) {
        for (i = 0; i + RATE <= clen; i += RATE) {
            aegis256_dec(m + i, c + i, blocks);
        }
    } else {
        CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
        for (i = 0; i + RATE <= clen; i += RATE) {
            aegis256_dec(dst, c + i, blocks);
        }
    }

    left = clen - i;
    if (left != 0) {
        size_t j;

        // Generate keystream without updating state
        aegis256_squeeze_keystream(st->buf, blocks);

        for (j = 0; j < left; j++) {
            if (m != NULL) {
                m[i + j]   = c[i + j] ^ st->buf[j];
                st->buf[j] = m[i + j];
            } else {
                uint8_t plaintext = c[i + j] ^ st->buf[j];
                st->buf[j]        = plaintext;
            }
        }
        st->pos = left;
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_decrypt_final(aegis256_state *st_, const uint8_t *mac, size_t maclen)
{
    aegis_blocks             blocks;
    CRYPTO_ALIGN(16) uint8_t computed_mac[32];
    _aegis256_state *const   st =
        (_aegis256_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                             ~(uintptr_t) (ALIGNMENT - 1));
    int ret;

    memcpy(blocks, st->blocks, sizeof blocks);

    // Plaintext was already output during _update; absorb cached plaintext into state
    if (st->pos != 0) {
        CRYPTO_ALIGN(ALIGNMENT) uint8_t tmp[RATE];
        memset(tmp, 0, sizeof tmp);
        memcpy(tmp, st->buf, st->pos);
        aegis256_absorb_rate(tmp, blocks);
    }

    aegis256_mac(computed_mac, maclen, st->adlen, st->mlen, blocks);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return ret;
}

static void
state_mac_init(aegis256_mac_state *st_, const uint8_t *npub, const uint8_t *k)
{
    aegis_blocks                    blocks;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t zero_nonce[32];
    _aegis256_mac_state *const      st =
        (_aegis256_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                 ~(uintptr_t) (ALIGNMENT - 1));

    COMPILER_ASSERT((sizeof *st) + ALIGNMENT <= sizeof *st_);
    st->pos = 0;

    memcpy(blocks, st->blocks, sizeof blocks);

    if (npub == NULL) {
        memset(zero_nonce, 0, sizeof zero_nonce);
        npub = zero_nonce;
    }

    aegis256_init(k, npub, blocks);

    memcpy(st->blocks0, blocks, sizeof blocks);
    memcpy(st->blocks, blocks, sizeof blocks);
    st->adlen = 0;
}

static int
state_mac_update(aegis256_mac_state *st_, const uint8_t *ad, size_t adlen)
{
    aegis_blocks               blocks;
    _aegis256_mac_state *const st =
        (_aegis256_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                 ~(uintptr_t) (ALIGNMENT - 1));
    size_t i;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    left = st->adlen % RATE;
    st->adlen += adlen;
    if (left != 0) {
        if (left + adlen < RATE) {
            memcpy(st->buf + left, ad, adlen);
            return 0;
        }
        memcpy(st->buf + left, ad, RATE - left);
        aegis256_absorb(st->buf, blocks);
        ad += RATE - left;
        adlen -= RATE - left;
    }
    for (i = 0; i + RATE * 2 <= adlen; i += RATE * 2) {
        aes_block_t msg0, msg1;

        msg0 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 0);
        msg1 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 1);
        COMPILER_ASSERT(AES_BLOCK_LENGTH * 2 == RATE * 2);

        aegis256_update(blocks, msg0);
        aegis256_update(blocks, msg1);
    }
    for (; i + RATE <= adlen; i += RATE) {
        aegis256_absorb(ad + i, blocks);
    }
    if (i < adlen) {
        memset(st->buf, 0, RATE);
        memcpy(st->buf, ad + i, adlen - i);
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen)
{
    aegis_blocks               blocks;
    _aegis256_mac_state *const st =
        (_aegis256_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                 ~(uintptr_t) (ALIGNMENT - 1));
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    left = st->adlen % RATE;
    if (left != 0) {
        memset(st->buf + left, 0, RATE - left);
        aegis256_absorb(st->buf, blocks);
    }
    aegis256_mac(mac, maclen, st->adlen, maclen, blocks);

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static void
state_mac_reset(aegis256_mac_state *st_)
{
    _aegis256_mac_state *const st =
        (_aegis256_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                 ~(uintptr_t) (ALIGNMENT - 1));
    st->adlen = 0;
    st->pos   = 0;
    memcpy(st->blocks, st->blocks0, sizeof(aegis_blocks));
}

static void
state_mac_clone(aegis256_mac_state *dst, const aegis256_mac_state *src)
{
    _aegis256_mac_state *const dst_ =
        (_aegis256_mac_state *) ((((uintptr_t) &dst->opaque) + (ALIGNMENT - 1)) &
                                 ~(uintptr_t) (ALIGNMENT - 1));
    const _aegis256_mac_state *const src_ =
        (const _aegis256_mac_state *) ((((uintptr_t) &src->opaque) + (ALIGNMENT - 1)) &
                                       ~(uintptr_t) (ALIGNMENT - 1));
    *dst_ = *src_;
}
