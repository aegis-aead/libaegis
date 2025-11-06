#define RATE      64
#define ALIGNMENT 64

typedef aes_block_t aegis_blocks[6];

static void
aegis256x4_init(const uint8_t *key, const uint8_t *nonce, aes_block_t *const state)
{
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t c0_[AES_BLOCK_LENGTH] = {
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90,
        0xe9, 0x79, 0x62, 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22,
        0x37, 0x59, 0x90, 0xe9, 0x79, 0x62, 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08,
        0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62, 0x00, 0x01, 0x01, 0x02,
        0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
    };
    static CRYPTO_ALIGN(AES_BLOCK_LENGTH) const uint8_t c1_[AES_BLOCK_LENGTH] = {
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73,
        0xb5, 0x28, 0xdd, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11,
        0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f,
        0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd, 0xdb, 0x3d, 0x18, 0x55,
        0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
    };

    const aes_block_t c0 = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1 = AES_BLOCK_LOAD(c1_);
    uint8_t           tmp[4 * 16];
    uint8_t           context_bytes[AES_BLOCK_LENGTH];
    aes_block_t       context;
    aes_block_t       k0, k1;
    aes_block_t       n0, n1;
    aes_block_t       k0_n0, k1_n1;
    int               i;

    memcpy(tmp, key, 16);
    memcpy(tmp + 16, key, 16);
    memcpy(tmp + 32, key, 16);
    memcpy(tmp + 48, key, 16);
    k0 = AES_BLOCK_LOAD(tmp);
    memcpy(tmp, key + 16, 16);
    memcpy(tmp + 16, key + 16, 16);
    memcpy(tmp + 32, key + 16, 16);
    memcpy(tmp + 48, key + 16, 16);
    k1 = AES_BLOCK_LOAD(tmp);

    memcpy(tmp, nonce, 16);
    memcpy(tmp + 16, nonce, 16);
    memcpy(tmp + 32, nonce, 16);
    memcpy(tmp + 48, nonce, 16);
    n0 = AES_BLOCK_LOAD(tmp);
    memcpy(tmp, nonce + 16, 16);
    memcpy(tmp + 16, nonce + 16, 16);
    memcpy(tmp + 32, nonce + 16, 16);
    memcpy(tmp + 48, nonce + 16, 16);
    n1 = AES_BLOCK_LOAD(tmp);

    k0_n0 = AES_BLOCK_XOR(k0, n0);
    k1_n1 = AES_BLOCK_XOR(k1, n1);

    memset(context_bytes, 0, sizeof context_bytes);
    context_bytes[0 * 16]     = 0x00;
    context_bytes[0 * 16 + 1] = 0x03;
    context_bytes[1 * 16]     = 0x01;
    context_bytes[1 * 16 + 1] = 0x03;
    context_bytes[2 * 16]     = 0x02;
    context_bytes[2 * 16 + 1] = 0x03;
    context_bytes[3 * 16]     = 0x03;
    context_bytes[3 * 16 + 1] = 0x03;
    context                   = AES_BLOCK_LOAD(context_bytes);

    state[0] = k0_n0;
    state[1] = k1_n1;
    state[2] = c1;
    state[3] = c0;
    state[4] = AES_BLOCK_XOR(k0, c0);
    state[5] = AES_BLOCK_XOR(k1, c1);
    for (i = 0; i < 4; i++) {
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[5] = AES_BLOCK_XOR(state[5], context);
        aegis256x4_update(state, k0);
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[5] = AES_BLOCK_XOR(state[5], context);
        aegis256x4_update(state, k1);
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[5] = AES_BLOCK_XOR(state[5], context);
        aegis256x4_update(state, k0_n0);
        state[3] = AES_BLOCK_XOR(state[3], context);
        state[5] = AES_BLOCK_XOR(state[5], context);
        aegis256x4_update(state, k1_n1);
    }
}

static void
aegis256x4_mac(uint8_t *mac, size_t maclen, uint64_t adlen, uint64_t mlen, aes_block_t *const state)
{
    uint8_t     mac_multi_0[AES_BLOCK_LENGTH];
    uint8_t     mac_multi_1[AES_BLOCK_LENGTH];
    aes_block_t tmp;
    int         i;

    tmp = AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AES_BLOCK_XOR(tmp, state[3]);

    for (i = 0; i < 7; i++) {
        aegis256x4_update(state, tmp);
    }

    if (maclen == 16) {
        tmp = AES_BLOCK_XOR(state[5], state[4]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac_multi_0, tmp);
        for (i = 0; i < 16; i++) {
            mac[i] = mac_multi_0[i] ^ mac_multi_0[1 * 16 + i] ^ mac_multi_0[2 * 16 + i] ^
                     mac_multi_0[3 * 16 + i];
        }
    } else if (maclen == 32) {
        tmp = AES_BLOCK_XOR(state[2], AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(mac_multi_0, tmp);
        for (i = 0; i < 16; i++) {
            mac[i] = mac_multi_0[i] ^ mac_multi_0[1 * 16 + i] ^ mac_multi_0[2 * 16 + i] ^
                     mac_multi_0[3 * 16 + i];
        }

        tmp = AES_BLOCK_XOR(state[5], AES_BLOCK_XOR(state[4], state[3]));
        AES_BLOCK_STORE(mac_multi_1, tmp);
        for (i = 0; i < 16; i++) {
            mac[i + 16] = mac_multi_1[i] ^ mac_multi_1[1 * 16 + i] ^ mac_multi_1[2 * 16 + i] ^
                          mac_multi_1[3 * 16 + i];
        }
    } else {
        memset(mac, 0, maclen);
    }
}

static inline void
aegis256x4_absorb(const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;

    msg = AES_BLOCK_LOAD(src);
    aegis256x4_update(state, msg);
}

static void
aegis256x4_enc(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;
    aes_block_t tmp;

    msg = AES_BLOCK_LOAD(src);
    tmp = AES_BLOCK_XOR(msg, state[5]);
    tmp = AES_BLOCK_XOR(tmp, state[4]);
    tmp = AES_BLOCK_XOR(tmp, state[1]);
    tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_AND(state[2], state[3]));
    AES_BLOCK_STORE(dst, tmp);

    aegis256x4_update(state, msg);
}

static void
aegis256x4_dec(uint8_t *const dst, const uint8_t *const src, aes_block_t *const state)
{
    aes_block_t msg;

    msg = AES_BLOCK_LOAD(src);
    msg = AES_BLOCK_XOR(msg, state[5]);
    msg = AES_BLOCK_XOR(msg, state[4]);
    msg = AES_BLOCK_XOR(msg, state[1]);
    msg = AES_BLOCK_XOR(msg, AES_BLOCK_AND(state[2], state[3]));
    AES_BLOCK_STORE(dst, msg);

    aegis256x4_update(state, msg);
}

static void
aegis256x4_declast(uint8_t *const dst, const uint8_t *const src, size_t len,
                   aes_block_t *const state)
{
    uint8_t     pad[RATE];
    aes_block_t msg;

    memset(pad, 0, sizeof pad);
    memcpy(pad, src, len);

    msg = AES_BLOCK_LOAD(pad);
    msg = AES_BLOCK_XOR(msg, state[5]);
    msg = AES_BLOCK_XOR(msg, state[4]);
    msg = AES_BLOCK_XOR(msg, state[1]);
    msg = AES_BLOCK_XOR(msg, AES_BLOCK_AND(state[2], state[3]));
    AES_BLOCK_STORE(pad, msg);

    memset(pad + len, 0, sizeof pad - len);
    memcpy(dst, pad, len);

    msg = AES_BLOCK_LOAD(pad);

    aegis256x4_update(state, msg);
}

static void
aegis256x4_mac_nr(uint8_t *mac, size_t maclen, uint64_t adlen, aes_block_t *state)
{
    uint8_t     t[2 * AES_BLOCK_LENGTH];
    uint8_t     r[RATE];
    aes_block_t tmp;
    int         i;
    const int   d = AES_BLOCK_LENGTH / 16;

    tmp = AES_BLOCK_LOAD_64x2(maclen << 3, adlen << 3);
    tmp = AES_BLOCK_XOR(tmp, state[3]);

    for (i = 0; i < 7; i++) {
        aegis256x4_update(state, tmp);
    }

    memset(r, 0, sizeof r);
    if (maclen == 16) {
#if AES_BLOCK_LENGTH > 16
        tmp = AES_BLOCK_XOR(state[5], state[4]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(t, tmp);

        for (i = 1; i < d; i++) {
            memcpy(r, t + i * 16, 16);
            aegis256x4_absorb(r, state);
        }
        tmp = AES_BLOCK_LOAD_64x2(maclen << 3, d);
        tmp = AES_BLOCK_XOR(tmp, state[3]);
        for (i = 0; i < 7; i++) {
            aegis256x4_update(state, tmp);
        }
#endif
        tmp = AES_BLOCK_XOR(state[5], state[4]);
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[3], state[2]));
        tmp = AES_BLOCK_XOR(tmp, AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(t, tmp);
        memcpy(mac, t, 16);
    } else if (maclen == 32) {
#if AES_BLOCK_LENGTH > 16
        tmp = AES_BLOCK_XOR(state[2], AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(t, tmp);
        tmp = AES_BLOCK_XOR(state[5], AES_BLOCK_XOR(state[4], state[3]));
        AES_BLOCK_STORE(t + AES_BLOCK_LENGTH, tmp);
        for (i = 1; i < d; i++) {
            memcpy(r, t + i * 16, 16);
            aegis256x4_absorb(r, state);
            memcpy(r, t + AES_BLOCK_LENGTH + i * 16, 16);
            aegis256x4_absorb(r, state);
        }
        tmp = AES_BLOCK_LOAD_64x2(maclen << 3, d);
        tmp = AES_BLOCK_XOR(tmp, state[3]);
        for (i = 0; i < 7; i++) {
            aegis256x4_update(state, tmp);
        }
#endif
        tmp = AES_BLOCK_XOR(state[2], AES_BLOCK_XOR(state[1], state[0]));
        AES_BLOCK_STORE(t, tmp);
        memcpy(mac, t, 16);
        tmp = AES_BLOCK_XOR(state[5], AES_BLOCK_XOR(state[4], state[3]));
        AES_BLOCK_STORE(t, tmp);
        memcpy(mac + 16, t, 16);
    } else {
        memset(mac, 0, maclen);
    }
}

static int
encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                 const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    aegis_blocks                    state;
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i;

    aegis256x4_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256x4_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis256x4_absorb(src, state);
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256x4_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis256x4_enc(dst, src, state);
        memcpy(c + i, dst, mlen % RATE);
    }

    aegis256x4_mac(mac, maclen, adlen, mlen, state);

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

    aegis256x4_init(k, npub, state);

    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256x4_absorb(ad + i, state);
    }
    if (adlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, ad + i, adlen % RATE);
        aegis256x4_absorb(src, state);
    }
    if (m != NULL) {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256x4_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0; i + RATE <= mlen; i += RATE) {
            aegis256x4_dec(dst, c + i, state);
        }
    }
    if (mlen % RATE) {
        if (m != NULL) {
            aegis256x4_declast(m + i, c + i, mlen % RATE, state);
        } else {
            aegis256x4_declast(dst, c + i, mlen % RATE, state);
        }
    }

    COMPILER_ASSERT(sizeof computed_mac >= 32);
    aegis256x4_mac(computed_mac, maclen, adlen, mlen, state);
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

    aegis256x4_init(k, npub, state);

    for (i = 0; i + RATE <= len; i += RATE) {
        aegis256x4_enc(out + i, src, state);
    }
    if (len % RATE) {
        aegis256x4_enc(dst, src, state);
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

    aegis256x4_init(k, npub, state);

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256x4_enc(c + i, m + i, state);
    }
    if (mlen % RATE) {
        memset(src, 0, RATE);
        memcpy(src, m + i, mlen % RATE);
        aegis256x4_enc(dst, src, state);
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

    aegis256x4_init(k, npub, state);

    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256x4_dec(m + i, c + i, state);
    }
    if (mlen % RATE) {
        aegis256x4_declast(m + i, c + i, mlen % RATE, state);
    }
}

typedef struct _aegis256x4_state {
    aegis_blocks blocks;
    uint8_t      buf[RATE];
    uint64_t     adlen;
    uint64_t     mlen;
    size_t       pos;
} _aegis256x4_state;

typedef struct _aegis256x4_mac_state {
    aegis_blocks blocks;
    aegis_blocks blocks0;
    uint8_t      buf[RATE];
    uint64_t     adlen;
    size_t       pos;
} _aegis256x4_mac_state;

static void
state_init(aegis256x4_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
           const uint8_t *k)
{
    aegis_blocks             blocks;
    _aegis256x4_state *const st =
        (_aegis256x4_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                               ~(uintptr_t) (ALIGNMENT - 1));
    size_t i;

    memcpy(blocks, st->blocks, sizeof blocks);

    COMPILER_ASSERT((sizeof *st) + ALIGNMENT <= sizeof *st_);
    st->mlen = 0;
    st->pos  = 0;

    aegis256x4_init(k, npub, blocks);
    for (i = 0; i + RATE <= adlen; i += RATE) {
        aegis256x4_absorb(ad + i, blocks);
    }
    if (adlen % RATE) {
        memset(st->buf, 0, RATE);
        memcpy(st->buf, ad + i, adlen % RATE);
        aegis256x4_absorb(st->buf, blocks);
    }
    st->adlen = adlen;

    memcpy(st->blocks, blocks, sizeof blocks);
}

static int
state_encrypt_update(aegis256x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                     const uint8_t *m, size_t mlen)
{
    aegis_blocks             blocks;
    _aegis256x4_state *const st =
        (_aegis256x4_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                               ~(uintptr_t) (ALIGNMENT - 1));
    size_t i = 0;
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    *written = 0;
    st->mlen += mlen;
    if (st->pos != 0) {
        const size_t available = (sizeof st->buf) - st->pos;
        const size_t n         = mlen < available ? mlen : available;

        if (n != 0) {
            memcpy(st->buf + st->pos, m + i, n);
            m += n;
            mlen -= n;
            st->pos += n;
        }
        if (st->pos == sizeof st->buf) {
            if (clen_max < RATE) {
                errno = ERANGE;
                return -1;
            }
            clen_max -= RATE;
            aegis256x4_enc(c, st->buf, blocks);
            *written += RATE;
            c += RATE;
            st->pos = 0;
        } else {
            return 0;
        }
    }
    if (clen_max < (mlen & ~(size_t) (RATE - 1))) {
        errno = ERANGE;
        return -1;
    }
    for (i = 0; i + RATE <= mlen; i += RATE) {
        aegis256x4_enc(c + i, m + i, blocks);
    }
    *written += i;
    left = mlen % RATE;
    if (left != 0) {
        memcpy(st->buf, m + i, left);
        st->pos = left;
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_encrypt_detached_final(aegis256x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                             uint8_t *mac, size_t maclen)
{
    aegis_blocks             blocks;
    _aegis256x4_state *const st =
        (_aegis256x4_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                               ~(uintptr_t) (ALIGNMENT - 1));
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];

    memcpy(blocks, st->blocks, sizeof blocks);

    *written = 0;
    if (clen_max < st->pos) {
        errno = ERANGE;
        return -1;
    }
    if (st->pos != 0) {
        memset(src, 0, sizeof src);
        memcpy(src, st->buf, st->pos);
        aegis256x4_enc(dst, src, blocks);
        memcpy(c, dst, st->pos);
    }
    aegis256x4_mac(mac, maclen, st->adlen, st->mlen, blocks);

    *written = st->pos;

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_encrypt_final(aegis256x4_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                    size_t maclen)
{
    aegis_blocks             blocks;
    _aegis256x4_state *const st =
        (_aegis256x4_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                               ~(uintptr_t) (ALIGNMENT - 1));
    CRYPTO_ALIGN(ALIGNMENT) uint8_t src[RATE];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];

    memcpy(blocks, st->blocks, sizeof blocks);

    *written = 0;
    if (clen_max < st->pos + maclen) {
        errno = ERANGE;
        return -1;
    }
    if (st->pos != 0) {
        memset(src, 0, sizeof src);
        memcpy(src, st->buf, st->pos);
        aegis256x4_enc(dst, src, blocks);
        memcpy(c, dst, st->pos);
    }
    aegis256x4_mac(c + st->pos, maclen, st->adlen, st->mlen, blocks);

    *written = st->pos + maclen;

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_decrypt_detached_update(aegis256x4_state *st_, uint8_t *m, size_t mlen_max, size_t *written,
                              const uint8_t *c, size_t clen)
{
    aegis_blocks             blocks;
    _aegis256x4_state *const st =
        (_aegis256x4_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                               ~(uintptr_t) (ALIGNMENT - 1));
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    size_t                          i = 0;
    size_t                          left;

    memcpy(blocks, st->blocks, sizeof blocks);

    *written = 0;
    st->mlen += clen;

    if (st->pos != 0) {
        const size_t available = (sizeof st->buf) - st->pos;
        const size_t n         = clen < available ? clen : available;

        if (n != 0) {
            memcpy(st->buf + st->pos, c, n);
            c += n;
            clen -= n;
            st->pos += n;
        }
        if (st->pos < (sizeof st->buf)) {
            return 0;
        }
        st->pos = 0;
        if (m != NULL) {
            if (mlen_max < RATE) {
                errno = ERANGE;
                return -1;
            }
            mlen_max -= RATE;
            aegis256x4_dec(m, st->buf, blocks);
            m += RATE;
        } else {
            aegis256x4_dec(dst, st->buf, blocks);
        }
        *written += RATE;
    }

    if (m != NULL) {
        if (mlen_max < (clen & ~(size_t) (RATE - 1))) {
            errno = ERANGE;
            return -1;
        }
        for (i = 0; i + RATE <= clen; i += RATE) {
            aegis256x4_dec(m + i, c + i, blocks);
        }
    } else {
        for (i = 0; i + RATE <= clen; i += RATE) {
            aegis256x4_dec(dst, c + i, blocks);
        }
    }
    *written += i;
    left = clen % RATE;
    if (left) {
        memcpy(st->buf, c + i, left);
        st->pos = left;
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_decrypt_detached_final(aegis256x4_state *st_, uint8_t *m, size_t mlen_max, size_t *written,
                             const uint8_t *mac, size_t maclen)
{
    aegis_blocks                    blocks;
    CRYPTO_ALIGN(16) uint8_t        computed_mac[32];
    CRYPTO_ALIGN(ALIGNMENT) uint8_t dst[RATE];
    _aegis256x4_state *const        st =
        (_aegis256x4_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                               ~(uintptr_t) (ALIGNMENT - 1));
    int ret;

    memcpy(blocks, st->blocks, sizeof blocks);

    *written = 0;
    if (st->pos != 0) {
        if (m != NULL) {
            if (mlen_max < st->pos) {
                errno = ERANGE;
                return -1;
            }
            aegis256x4_declast(m, st->buf, st->pos, blocks);
        } else {
            aegis256x4_declast(dst, st->buf, st->pos, blocks);
        }
    }
    aegis256x4_mac(computed_mac, maclen, st->adlen, st->mlen, blocks);
    ret = -1;
    if (maclen == 16) {
        ret = aegis_verify_16(computed_mac, mac);
    } else if (maclen == 32) {
        ret = aegis_verify_32(computed_mac, mac);
    }
    if (ret == 0) {
        *written = st->pos;
    } else {
        memset(m, 0, st->pos);
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return ret;
}

static void
state_mac_init(aegis256x4_mac_state *st_, const uint8_t *npub, const uint8_t *k)
{
    aegis_blocks                 blocks;
    _aegis256x4_mac_state *const st =
        (_aegis256x4_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                   ~(uintptr_t) (ALIGNMENT - 1));

    COMPILER_ASSERT((sizeof *st) + ALIGNMENT <= sizeof *st_);
    st->pos = 0;

    memcpy(blocks, st->blocks, sizeof blocks);

    aegis256x4_init(k, npub, blocks);

    memcpy(st->blocks0, blocks, sizeof blocks);
    memcpy(st->blocks, blocks, sizeof blocks);
    st->adlen = 0;
}

static int
state_mac_update(aegis256x4_mac_state *st_, const uint8_t *ad, size_t adlen)
{
    aegis_blocks                 blocks;
    _aegis256x4_mac_state *const st =
        (_aegis256x4_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
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
        aegis256x4_absorb(st->buf, blocks);
        ad += RATE - left;
        adlen -= RATE - left;
    }
    for (i = 0; i + RATE * 2 <= adlen; i += RATE * 2) {
        aes_block_t msg0, msg1;

        msg0 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 0);
        msg1 = AES_BLOCK_LOAD(ad + i + AES_BLOCK_LENGTH * 1);
        COMPILER_ASSERT(AES_BLOCK_LENGTH * 2 == RATE * 2);

        aegis256x4_update(blocks, msg0);
        aegis256x4_update(blocks, msg1);
    }
    for (; i + RATE <= adlen; i += RATE) {
        aegis256x4_absorb(ad + i, blocks);
    }
    if (i < adlen) {
        memset(st->buf, 0, RATE);
        memcpy(st->buf, ad + i, adlen - i);
    }

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static int
state_mac_final(aegis256x4_mac_state *st_, uint8_t *mac, size_t maclen)
{
    aegis_blocks                 blocks;
    _aegis256x4_mac_state *const st =
        (_aegis256x4_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                   ~(uintptr_t) (ALIGNMENT - 1));
    size_t left;

    memcpy(blocks, st->blocks, sizeof blocks);

    left = st->adlen % RATE;
    if (left != 0) {
        memset(st->buf + left, 0, RATE - left);
        aegis256x4_absorb(st->buf, blocks);
    }
    aegis256x4_mac_nr(mac, maclen, st->adlen, blocks);

    memcpy(st->blocks, blocks, sizeof blocks);

    return 0;
}

static void
state_mac_reset(aegis256x4_mac_state *st_)
{
    _aegis256x4_mac_state *const st =
        (_aegis256x4_mac_state *) ((((uintptr_t) &st_->opaque) + (ALIGNMENT - 1)) &
                                   ~(uintptr_t) (ALIGNMENT - 1));
    st->adlen = 0;
    st->pos   = 0;
    memcpy(st->blocks, st->blocks0, sizeof(aegis_blocks));
}

static void
state_mac_clone(aegis256x4_mac_state *dst, const aegis256x4_mac_state *src)
{
    _aegis256x4_mac_state *const dst_ =
        (_aegis256x4_mac_state *) ((((uintptr_t) &dst->opaque) + (ALIGNMENT - 1)) &
                                   ~(uintptr_t) (ALIGNMENT - 1));
    const _aegis256x4_mac_state *const src_ =
        (const _aegis256x4_mac_state *) ((((uintptr_t) &src->opaque) + (ALIGNMENT - 1)) &
                                         ~(uintptr_t) (ALIGNMENT - 1));
    *dst_ = *src_;
}