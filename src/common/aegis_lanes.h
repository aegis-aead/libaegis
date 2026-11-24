/*
 * When the X2 or X4 state doesn't fit in the 16 vector registers, updating it in one go spills on every block.
 * So the input is processed one group of lanes at a time, over short chunks that are still in the L1 cache when the next group reads them.
 *
 * When a single group holds the whole state, only encrypt_detached() and decrypt_detached() use it, on a copy of the state, from AEGIS_LANES_MIN bytes.
 */

#if AEGIS_LANES_WORDS == 8
#    define AEGIS_LANES_RATE (2 * AES_BLOCK_LENGTH)
#elif AEGIS_LANES_WORDS == 6
#    define AEGIS_LANES_RATE AES_BLOCK_LENGTH
#else
#    error "AEGIS_LANES_WORDS must be 6 or 8"
#endif

#define AEGIS_LANES_WHOLE ((size_t) -1 - ((size_t) -1) % AEGIS_LANES_RATE)

#if AES_LANE_LENGTH == AES_BLOCK_LENGTH
#    define AEGIS_LANES_COPY
#    define AEGIS_LANES_CHUNK AEGIS_LANES_WHOLE
#    ifndef AEGIS_LANES_MIN
#        error "AEGIS_LANES_MIN must be defined with a single group"
#    endif
#else
#    define AEGIS_LANES_MIN AEGIS_LANES_RATE
#endif

/* 512 bytes was the fastest on Zen 4: with short chunks, the CPU overlaps consecutive groups. */
#ifndef AEGIS_LANES_CHUNK
#    define AEGIS_LANES_CHUNK 512
#endif

#ifndef AES_LANE_LOOP_ALIGN
#    define AES_LANE_LOOP_ALIGN
#endif

typedef aes_lane_t aegis_lanes_state[AEGIS_LANES_WORDS];

static AEGIS_ALWAYS_INLINE void
aegis_lanes_load(aes_lane_t *const s, const uint8_t *st)
{
    s[0] = AES_LANE_LOAD(st + 0 * AES_BLOCK_LENGTH);
    s[1] = AES_LANE_LOAD(st + 1 * AES_BLOCK_LENGTH);
    s[2] = AES_LANE_LOAD(st + 2 * AES_BLOCK_LENGTH);
    s[3] = AES_LANE_LOAD(st + 3 * AES_BLOCK_LENGTH);
    s[4] = AES_LANE_LOAD(st + 4 * AES_BLOCK_LENGTH);
    s[5] = AES_LANE_LOAD(st + 5 * AES_BLOCK_LENGTH);
#if AEGIS_LANES_WORDS == 8
    s[6] = AES_LANE_LOAD(st + 6 * AES_BLOCK_LENGTH);
    s[7] = AES_LANE_LOAD(st + 7 * AES_BLOCK_LENGTH);
#endif
}

static AEGIS_ALWAYS_INLINE void
aegis_lanes_store(uint8_t *st, const aes_lane_t *const s)
{
    AES_LANE_STORE(st + 0 * AES_BLOCK_LENGTH, s[0]);
    AES_LANE_STORE(st + 1 * AES_BLOCK_LENGTH, s[1]);
    AES_LANE_STORE(st + 2 * AES_BLOCK_LENGTH, s[2]);
    AES_LANE_STORE(st + 3 * AES_BLOCK_LENGTH, s[3]);
    AES_LANE_STORE(st + 4 * AES_BLOCK_LENGTH, s[4]);
    AES_LANE_STORE(st + 5 * AES_BLOCK_LENGTH, s[5]);
#if AEGIS_LANES_WORDS == 8
    AES_LANE_STORE(st + 6 * AES_BLOCK_LENGTH, s[6]);
    AES_LANE_STORE(st + 7 * AES_BLOCK_LENGTH, s[7]);
#endif
}

/*
 * A lane header that defines AES_LANE_SHA3 also provides XOR3, BCAX, NOT, ENC0 and ENC0_NOT.
 * With 8 words, the bulk loop then keeps words 3 and 7 inverted, so that the keystream can use BCAX.
 * With 6 words, this doesn't save anything.
 */
#if defined(AES_LANE_SHA3) && AEGIS_LANES_WORDS == 8
#    define AEGIS_LANES_INVERT 1
#else
#    define AEGIS_LANES_INVERT 0
#endif

/* AES(a) ^ b ^ d, where a may be inverted. */
static AEGIS_ALWAYS_INLINE aes_lane_t
aegis_lanes_enc_xor(const aes_lane_t a, const int inverted, const aes_lane_t b, const aes_lane_t d)
{
#ifdef AES_LANE_SHA3
    if (inverted) {
        return AES_LANE_XOR3(b, AES_LANE_ENC0_NOT(a), d);
    }
    return AES_LANE_XOR3(b, AES_LANE_ENC0(a), d);
#else
    (void) inverted;
    return AES_LANE_XOR(AES_LANE_ENC(a, b), d);
#endif
}

#if AEGIS_LANES_WORDS == 8

static AEGIS_ALWAYS_INLINE void
aegis_lanes_update_inv(aes_lane_t *const s, const aes_lane_t d1, const aes_lane_t d2,
                       const int inverted)
{
    aes_lane_t t;

    t    = s[7];
    s[7] = AES_LANE_ENC(s[6], s[7]);
    s[6] = AES_LANE_ENC(s[5], s[6]);
    s[5] = AES_LANE_ENC(s[4], s[5]);
    s[4] = aegis_lanes_enc_xor(s[3], inverted, s[4], d2);
    s[3] = AES_LANE_ENC(s[2], s[3]);
    s[2] = AES_LANE_ENC(s[1], s[2]);
    s[1] = AES_LANE_ENC(s[0], s[1]);
    s[0] = aegis_lanes_enc_xor(t, inverted, s[0], d1);
}

static AEGIS_ALWAYS_INLINE void
aegis_lanes_update(aes_lane_t *const s, const aes_lane_t d1, const aes_lane_t d2)
{
    aegis_lanes_update_inv(s, d1, d2, 0);
}

#else

static AEGIS_ALWAYS_INLINE void
aegis_lanes_update(aes_lane_t *const s, const aes_lane_t d)
{
    aes_lane_t t;

    t    = s[5];
    s[5] = AES_LANE_ENC(s[4], s[5]);
    s[4] = AES_LANE_ENC(s[3], s[4]);
    s[3] = AES_LANE_ENC(s[2], s[3]);
    s[2] = AES_LANE_ENC(s[1], s[2]);
    s[1] = AES_LANE_ENC(s[0], s[1]);
    s[0] = aegis_lanes_enc_xor(t, 0, s[0], d);
}

#endif

/* off and end include the position of the group within a block. */
static AEGIS_ALWAYS_INLINE void
aegis_lanes_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st,
                const enum aegis_bulk_operation operation, const int store_output)
{
    aegis_lanes_state s;
    size_t            i;

    aegis_lanes_load(s, st);
#if AEGIS_LANES_INVERT
    s[3] = AES_LANE_NOT(s[3]);
    s[7] = AES_LANE_NOT(s[7]);
#endif
    AES_LANE_LOOP_ALIGN
    for (i = off; i < end; i += AEGIS_LANES_RATE) {
#if AEGIS_LANES_WORDS == 8
        aes_lane_t m0, m1, z0, z1;

        if (operation == AEGIS_BULK_STREAM) {
            m0 = m1 = AES_LANE_ZERO();
        } else {
            m0 = AES_LANE_LOAD(src + i);
            m1 = AES_LANE_LOAD(src + i + AES_BLOCK_LENGTH);
        }
        if (operation != AEGIS_BULK_ABSORB) {
#    if AEGIS_LANES_INVERT
            z0 = AES_LANE_BCAX(AES_LANE_XOR3(m0, s[6], s[1]), s[2], s[3]);
            z1 = AES_LANE_BCAX(AES_LANE_XOR3(m1, s[5], s[2]), s[6], s[7]);
#    else
            z0 = AES_LANE_XOR(AES_LANE_XOR(s[6], s[1]), AES_LANE_AND(s[2], s[3]));
            z1 = AES_LANE_XOR(AES_LANE_XOR(s[5], s[2]), AES_LANE_AND(s[6], s[7]));
            z0 = AES_LANE_XOR(z0, m0);
            z1 = AES_LANE_XOR(z1, m1);
#    endif
            if (store_output) {
                AES_LANE_STORE(dst + i, z0);
                AES_LANE_STORE(dst + i + AES_BLOCK_LENGTH, z1);
            }
            if (operation == AEGIS_BULK_DECRYPT) {
                m0 = z0;
                m1 = z1;
            } else if (operation == AEGIS_BULK_STREAM_XOR) {
                m0 = m1 = AES_LANE_ZERO();
            }
        }
        aegis_lanes_update_inv(s, m0, m1, AEGIS_LANES_INVERT);
#else
        aes_lane_t m, z;

        if (operation == AEGIS_BULK_STREAM) {
            m = AES_LANE_ZERO();
        } else {
            m = AES_LANE_LOAD(src + i);
        }
        if (operation != AEGIS_BULK_ABSORB) {
            z = AES_LANE_XOR(AES_LANE_XOR(s[5], s[4]), s[1]);
            z = AES_LANE_XOR(AES_LANE_XOR(z, AES_LANE_AND(s[2], s[3])), m);
            if (store_output) {
                AES_LANE_STORE(dst + i, z);
            }
            if (operation == AEGIS_BULK_DECRYPT) {
                m = z;
            } else if (operation == AEGIS_BULK_STREAM_XOR) {
                m = AES_LANE_ZERO();
            }
        }
        aegis_lanes_update(s, m);
#endif
    }
#if AEGIS_LANES_INVERT
    s[3] = AES_LANE_NOT(s[3]);
    s[7] = AES_LANE_NOT(s[7]);
#endif
    aegis_lanes_store(st, s);
}

typedef void (*aegis_lanes_run_fn)(uint8_t *dst, const uint8_t *src, size_t off, size_t end,
                                   uint8_t *st);

static AEGIS_ALWAYS_INLINE size_t
aegis_lanes_chunks(uint8_t *dst, const uint8_t *src, size_t full, aes_block_t *state,
                   const aegis_lanes_run_fn run)
{
#ifdef AEGIS_LANES_COPY
    aes_block_t copy[AEGIS_LANES_WORDS];
    uint8_t    *st = (uint8_t *) (void *) copy;
#else
    uint8_t *st = (uint8_t *) (void *) state;
#endif
    size_t off, end, lane;

    COMPILER_ASSERT(AEGIS_LANES_CHUNK % AEGIS_LANES_RATE == 0);
    COMPILER_ASSERT(AES_BLOCK_LENGTH % AES_LANE_LENGTH == 0);

#ifdef AEGIS_LANES_COPY
    memcpy(copy, state, sizeof copy);
#else
    /* dst less than full bytes away from src: a group could overwrite input that the next groups haven't read yet. */
    if ((uintptr_t) dst - (uintptr_t) src + (full - 1) < 2 * full - 1 && dst != src) {
        return 0;
    }
#endif
    for (off = 0; off < full; off = end) {
        end = full - off > AEGIS_LANES_CHUNK ? off + AEGIS_LANES_CHUNK : full;
        for (lane = 0; lane < AES_BLOCK_LENGTH; lane += AES_LANE_LENGTH) {
            run(dst, src, off + lane, end + lane, st + lane);
        }
    }
#ifdef AEGIS_LANES_COPY
    memcpy(state, copy, sizeof copy);
#endif

    return full;
}

static AEGIS_ALWAYS_INLINE size_t
aegis_lanes_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state,
                 const aegis_lanes_run_fn run)
{
    const size_t full = len - len % AEGIS_LANES_RATE;

    if (full < AEGIS_LANES_MIN) {
        return 0;
    }
    return aegis_lanes_chunks(dst, src, full, state, run);
}

/* The run functions are not inlined, so that the compiler can't interleave the groups again. */

static AEGIS_NOINLINE void
aegis_lanes_encrypt_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st)
{
    aegis_lanes_run(dst, src, off, end, st, AEGIS_BULK_ENCRYPT, 1);
}

static inline size_t
aegis_lanes_encrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis_lanes_bulk(dst, src, len, state, aegis_lanes_encrypt_run);
}

#ifndef AEGIS_DECRYPT_BULK
static AEGIS_NOINLINE void
aegis_lanes_decrypt_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st)
{
    aegis_lanes_run(dst, src, off, end, st, AEGIS_BULK_DECRYPT, 1);
}

static AEGIS_NOINLINE void
aegis_lanes_verify_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st)
{
    aegis_lanes_run(dst, src, off, end, st, AEGIS_BULK_DECRYPT, 0);
}

static inline size_t
aegis_lanes_decrypt_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    if (dst == NULL) {
        return aegis_lanes_bulk(dst, src, len, state, aegis_lanes_verify_run);
    }
    return aegis_lanes_bulk(dst, src, len, state, aegis_lanes_decrypt_run);
}

#    ifdef AEGIS_LANES_COPY
#        define AEGIS_DECRYPT_DETACHED_BULK              aegis_lanes_decrypt_bulk
#        define AEGIS_DECRYPT_DETACHED_BULK_MIN          AEGIS_LANES_MIN
#        define AEGIS_DECRYPT_BULK(dst, src, len, state) 0
#    else
#        define AEGIS_DECRYPT_BULK aegis_lanes_decrypt_bulk
#    endif
#endif

#ifdef AEGIS_LANES_COPY

#    define AEGIS_ENCRYPT_DETACHED_BULK                 aegis_lanes_encrypt_bulk
#    define AEGIS_ENCRYPT_DETACHED_BULK_MIN             AEGIS_LANES_MIN
#    define AEGIS_ENCRYPT_BULK(dst, src, len, state)    0
#    define AEGIS_ABSORB_BULK(dst, src, len, state)     0
#    define AEGIS_STREAM_BULK(dst, src, len, state)     0
#    define AEGIS_STREAM_XOR_BULK(dst, src, len, state) 0

#else

#    define AEGIS_ENCRYPT_BULK aegis_lanes_encrypt_bulk

static AEGIS_NOINLINE void
aegis_lanes_absorb_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st)
{
    aegis_lanes_run(dst, src, off, end, st, AEGIS_BULK_ABSORB, 0);
}

static inline size_t
aegis_lanes_absorb_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis_lanes_bulk(dst, src, len, state, aegis_lanes_absorb_run);
}

#    define AEGIS_ABSORB_BULK aegis_lanes_absorb_bulk

static AEGIS_NOINLINE void
aegis_lanes_stream_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st)
{
    aegis_lanes_run(dst, src, off, end, st, AEGIS_BULK_STREAM, 1);
}

/* src is an unused zero block, which mustn't look like an overlap. */
static inline size_t
aegis_lanes_stream_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    (void) src;
    return aegis_lanes_bulk(dst, NULL, len, state, aegis_lanes_stream_run);
}

#    define AEGIS_STREAM_BULK aegis_lanes_stream_bulk

static AEGIS_NOINLINE void
aegis_lanes_stream_xor_run(uint8_t *dst, const uint8_t *src, size_t off, size_t end, uint8_t *st)
{
    aegis_lanes_run(dst, src, off, end, st, AEGIS_BULK_STREAM_XOR, 1);
}

static inline size_t
aegis_lanes_stream_xor_bulk(uint8_t *dst, const uint8_t *src, size_t len, aes_block_t *state)
{
    return aegis_lanes_bulk(dst, src, len, state, aegis_lanes_stream_xor_run);
}

#    define AEGIS_STREAM_XOR_BULK         aegis_lanes_stream_xor_bulk

/* The state is in memory anyway, so the incremental functions use it in place instead of copying it. */
#    define AEGIS_STATE_DECLARE(blocks)   aes_block_t *blocks
#    define AEGIS_STATE_BIND(blocks, src) ((blocks) = (src))
#    define AEGIS_STATE_LOAD(blocks, src) ((blocks) = (src))
#    define AEGIS_STATE_SAVE(dst, blocks) ((void) 0)

static AEGIS_ALWAYS_INLINE aes_lane_t
aegis_lanes_broadcast(const uint8_t *x)
#    ifdef AES_LANE_BROADCAST128
{
    return AES_LANE_BROADCAST128(x);
}
#    else
{
    uint8_t buf[AES_LANE_LENGTH];
    size_t  i;

    for (i = 0; i < AES_LANE_LENGTH; i += 16) {
        memcpy(buf + i, x, 16);
    }
    return AES_LANE_LOAD(buf);
}
#    endif

static AEGIS_NOINLINE void
aegis_lanes_init_run(const uint8_t *key, const uint8_t *nonce, size_t lane, uint8_t *st)
{
    static const uint8_t c0_[16] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                                     0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    static const uint8_t c1_[16] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
                                     0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
    /* The context of lane i is (i, number of lanes - 1), zero padded. */
    static const uint8_t contexts_[64] = {
        0, AES_BLOCK_LENGTH / 16 - 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, AES_BLOCK_LENGTH / 16 - 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, AES_BLOCK_LENGTH / 16 - 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        3, AES_BLOCK_LENGTH / 16 - 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    aegis_lanes_state s;
    aes_lane_t        c0, c1, context;
    int               j;

    COMPILER_ASSERT(AES_BLOCK_LENGTH <= sizeof contexts_);
    context = AES_LANE_LOAD(contexts_ + lane);
    c0      = aegis_lanes_broadcast(c0_);
    c1      = aegis_lanes_broadcast(c1_);

#    if AEGIS_LANES_WORDS == 8
    {
        const aes_lane_t k  = aegis_lanes_broadcast(key);
        const aes_lane_t n  = aegis_lanes_broadcast(nonce);
        const aes_lane_t kn = AES_LANE_XOR(k, n);

        s[0] = kn;
        s[1] = c1;
        s[2] = c0;
        s[3] = c1;
        s[4] = kn;
        s[5] = AES_LANE_XOR(k, c0);
        s[6] = AES_LANE_XOR(k, c1);
        s[7] = AES_LANE_XOR(k, c0);
        for (j = 0; j < 10; j++) {
            s[3] = AES_LANE_XOR(s[3], context);
            s[7] = AES_LANE_XOR(s[7], context);
            aegis_lanes_update(s, n, k);
        }
    }
#    else
    {
        const aes_lane_t k0    = aegis_lanes_broadcast(key);
        const aes_lane_t k1    = aegis_lanes_broadcast(key + 16);
        const aes_lane_t k0_n0 = AES_LANE_XOR(k0, aegis_lanes_broadcast(nonce));
        const aes_lane_t k1_n1 = AES_LANE_XOR(k1, aegis_lanes_broadcast(nonce + 16));

        s[0] = k0_n0;
        s[1] = k1_n1;
        s[2] = c1;
        s[3] = c0;
        s[4] = AES_LANE_XOR(k0, c0);
        s[5] = AES_LANE_XOR(k1, c1);
        for (j = 0; j < 4; j++) {
            s[3] = AES_LANE_XOR(s[3], context);
            s[5] = AES_LANE_XOR(s[5], context);
            aegis_lanes_update(s, k0);
            s[3] = AES_LANE_XOR(s[3], context);
            s[5] = AES_LANE_XOR(s[5], context);
            aegis_lanes_update(s, k1);
            s[3] = AES_LANE_XOR(s[3], context);
            s[5] = AES_LANE_XOR(s[5], context);
            aegis_lanes_update(s, k0_n0);
            s[3] = AES_LANE_XOR(s[3], context);
            s[5] = AES_LANE_XOR(s[5], context);
            aegis_lanes_update(s, k1_n1);
        }
    }
#    endif
    aegis_lanes_store(st, s);
}

static AEGIS_ALWAYS_INLINE void
aegis_lanes_init(const uint8_t *key, const uint8_t *nonce, aes_block_t *state)
{
    uint8_t *st = (uint8_t *) (void *) state;
    size_t   lane;

    for (lane = 0; lane < AES_BLOCK_LENGTH; lane += AES_LANE_LENGTH) {
        aegis_lanes_init_run(key, nonce, lane, st + lane);
    }
}

#    define AEGIS_LANES_INIT aegis_lanes_init

static AEGIS_NOINLINE void
aegis_lanes_mac_run(uint8_t *t0, uint8_t *t1, size_t lane, uint64_t lo, uint64_t hi, size_t maclen,
                    uint8_t *st)
{
    const aes_lane_t  lengths = AES_LANE_LOAD_64x2(hi, lo);
    aegis_lanes_state s;
    aes_lane_t        tmp;
    int               j;

    aegis_lanes_load(s, st);
#    if AEGIS_LANES_WORDS == 8
    tmp = AES_LANE_XOR(lengths, s[2]);
    for (j = 0; j < 7; j++) {
        aegis_lanes_update(s, tmp, tmp);
    }
    if (maclen == 16) {
        tmp = AES_LANE_XOR(s[6], AES_LANE_XOR(s[5], s[4]));
        tmp = AES_LANE_XOR(tmp, AES_LANE_XOR(s[3], s[2]));
        tmp = AES_LANE_XOR(tmp, AES_LANE_XOR(s[1], s[0]));
        AES_LANE_STORE(t0 + lane, tmp);
    } else if (maclen == 32) {
        tmp = AES_LANE_XOR(s[3], s[2]);
        tmp = AES_LANE_XOR(tmp, AES_LANE_XOR(s[1], s[0]));
        AES_LANE_STORE(t0 + lane, tmp);
        tmp = AES_LANE_XOR(s[7], s[6]);
        tmp = AES_LANE_XOR(tmp, AES_LANE_XOR(s[5], s[4]));
        AES_LANE_STORE(t1 + lane, tmp);
    }
#    else
    tmp = AES_LANE_XOR(lengths, s[3]);
    for (j = 0; j < 7; j++) {
        aegis_lanes_update(s, tmp);
    }
    if (maclen == 16) {
        tmp = AES_LANE_XOR(s[5], s[4]);
        tmp = AES_LANE_XOR(tmp, AES_LANE_XOR(s[3], s[2]));
        tmp = AES_LANE_XOR(tmp, AES_LANE_XOR(s[1], s[0]));
        AES_LANE_STORE(t0 + lane, tmp);
    } else if (maclen == 32) {
        tmp = AES_LANE_XOR(s[2], AES_LANE_XOR(s[1], s[0]));
        AES_LANE_STORE(t0 + lane, tmp);
        tmp = AES_LANE_XOR(s[5], AES_LANE_XOR(s[4], s[3]));
        AES_LANE_STORE(t1 + lane, tmp);
    }
#    endif
    aegis_lanes_store(st, s);
}

static AEGIS_ALWAYS_INLINE void
aegis_lanes_mac_tags(uint8_t *t0, uint8_t *t1, size_t maclen, uint64_t lo, uint64_t hi,
                     aes_block_t *state)
{
    uint8_t *st = (uint8_t *) (void *) state;
    size_t   lane;

    for (lane = 0; lane < AES_BLOCK_LENGTH; lane += AES_LANE_LENGTH) {
        aegis_lanes_mac_run(t0, t1, lane, lo, hi, maclen, st + lane);
    }
}

static inline void
aegis_lanes_mac_fold(uint8_t *dst, const uint8_t *src)
{
    uint64_t lo = 0, hi = 0, x;
    int      i;

    for (i = 0; i < AES_BLOCK_LENGTH; i += 16) {
        memcpy(&x, src + i, 8);
        lo ^= x;
        memcpy(&x, src + i + 8, 8);
        hi ^= x;
    }
    memcpy(dst, &lo, 8);
    memcpy(dst + 8, &hi, 8);
}

static AEGIS_ALWAYS_INLINE void
aegis_lanes_mac(uint8_t *mac, size_t maclen, uint64_t adlen, uint64_t mlen, aes_block_t *state)
{
    uint8_t t0[AES_BLOCK_LENGTH];
    uint8_t t1[AES_BLOCK_LENGTH];

    aegis_lanes_mac_tags(t0, t1, maclen, adlen << 3, mlen << 3, state);
    if (maclen == 16) {
        aegis_lanes_mac_fold(mac, t0);
    } else if (maclen == 32) {
        aegis_lanes_mac_fold(mac, t0);
        aegis_lanes_mac_fold(mac + 16, t1);
    } else {
        memset(mac, 0, maclen);
    }
}

#    define AEGIS_LANES_MAC aegis_lanes_mac

static AEGIS_ALWAYS_INLINE void
aegis_lanes_mac_finalize(size_t maclen, uint64_t adlen, aes_block_t *state)
{
    uint8_t   t[2 * AES_BLOCK_LENGTH];
    uint8_t   r[AEGIS_LANES_RATE];
    int       i;
    const int d = AES_BLOCK_LENGTH / 16;

    aegis_lanes_mac_tags(t, t + AES_BLOCK_LENGTH, maclen, adlen << 3, (uint64_t) maclen << 3,
                         state);

    memset(r, 0, sizeof r);
    if (maclen == 16) {
#    if AEGIS_LANES_WORDS == 8
        for (i = 0; i < d / 2; i++) {
            memcpy(r, t + i * 32, 16);
            memcpy(r + AEGIS_LANES_RATE / 2, t + i * 32 + 16, 16);
            aegis_lanes_absorb_bulk(NULL, r, AEGIS_LANES_RATE, state);
        }
#    else
        for (i = 1; i < d; i++) {
            memcpy(r, t + i * 16, 16);
            aegis_lanes_absorb_bulk(NULL, r, AEGIS_LANES_RATE, state);
        }
#    endif
        aegis_lanes_mac_tags(NULL, NULL, 0, d, (uint64_t) maclen << 3, state);
    } else if (maclen == 32) {
        for (i = 1; i < d; i++) {
            memcpy(r, t + i * 16, 16);
#    if AEGIS_LANES_WORDS == 8
            memcpy(r + AEGIS_LANES_RATE / 2, t + AES_BLOCK_LENGTH + i * 16, 16);
            aegis_lanes_absorb_bulk(NULL, r, AEGIS_LANES_RATE, state);
#    else
            aegis_lanes_absorb_bulk(NULL, r, AEGIS_LANES_RATE, state);
            memcpy(r, t + AES_BLOCK_LENGTH + i * 16, 16);
            aegis_lanes_absorb_bulk(NULL, r, AEGIS_LANES_RATE, state);
#    endif
        }
        aegis_lanes_mac_tags(NULL, NULL, 0, d, (uint64_t) maclen << 3, state);
    }
}

#    define AEGIS_LANES_MAC_FINALIZE aegis_lanes_mac_finalize

#endif
