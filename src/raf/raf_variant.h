#define CONCAT_(a, b)     a##b
#define CONCAT(a, b)      CONCAT_(a, b)
#define CONCAT3_(a, b, c) a##b##c
#define CONCAT3(a, b, c)  CONCAT3_(a, b, c)

#define FN(name)       CONCAT3(VARIANT, _raf_, name)
#define CTX_TYPE       CONCAT3(VARIANT, _raf_, ctx)
#define MAC_STATE_TYPE CONCAT3(VARIANT, _mac_, state)

#define AAD_BYTES     44
#define KDF_CONST     "aegis-raf-kdf-v1"
#define KDF_CONST_LEN 16

static void
derive_keys(uint8_t *enc_key, uint8_t *hdr_key, const uint8_t *master_key,
            const uint8_t file_id[AEGIS_RAF_FILE_ID_BYTES])
{
    uint8_t kdf_nonce[NPUBBYTES];
    uint8_t key_material[KEYBYTES * 2];
    size_t  i;

    memcpy(kdf_nonce, file_id, NPUBBYTES);
    for (i = 0; i < KDF_CONST_LEN && i < NPUBBYTES; i++) {
        kdf_nonce[i] ^= (uint8_t) KDF_CONST[i];
    }

    VARIANT_stream(key_material, sizeof key_material, kdf_nonce, master_key);

    memcpy(enc_key, key_material, KEYBYTES);
    memcpy(hdr_key, key_material + KEYBYTES, KEYBYTES);

    memset(key_material, 0, sizeof key_material);
    memset(kdf_nonce, 0, sizeof kdf_nonce);
}

static int
compute_header_mac(uint8_t mac[AEGIS_RAF_TAG_BYTES], const uint8_t hdr[AEGIS_RAF_HEADER_SIZE],
                   const uint8_t *hdr_key)
{
    MAC_STATE_TYPE st;
    VARIANT_mac_init(&st, hdr_key, NULL);
    if (VARIANT_mac_update(&st, hdr, AEGIS_RAF_HEADER_SIZE - AEGIS_RAF_TAG_BYTES) != 0) {
        memset(&st, 0, sizeof st);
        return -1;
    }
    if (VARIANT_mac_final(&st, mac, AEGIS_RAF_TAG_BYTES) != 0) {
        memset(&st, 0, sizeof st);
        return -1;
    }
    memset(&st, 0, sizeof st);
    return 0;
}

static int
verify_header_mac(const uint8_t hdr[AEGIS_RAF_HEADER_SIZE], const uint8_t *hdr_key)
{
    MAC_STATE_TYPE st;
    int            ret;

    VARIANT_mac_init(&st, hdr_key, NULL);
    if (VARIANT_mac_update(&st, hdr, AEGIS_RAF_HEADER_SIZE - AEGIS_RAF_TAG_BYTES) != 0) {
        memset(&st, 0, sizeof st);
        return -1;
    }
    ret = VARIANT_mac_verify(&st, hdr + AEGIS_RAF_HEADER_SIZE - AEGIS_RAF_TAG_BYTES,
                             AEGIS_RAF_TAG_BYTES);
    memset(&st, 0, sizeof st);
    if (ret != 0) {
        errno = EBADMSG;
    }
    return ret;
}

static inline uint64_t
record_size(uint32_t chunk_size)
{
    return (uint64_t) NPUBBYTES + chunk_size + AEGIS_RAF_TAG_BYTES;
}

static inline uint64_t
get_chunk_offset(uint32_t chunk_size, uint64_t chunk_idx)
{
    return AEGIS_RAF_HEADER_SIZE + chunk_idx * record_size(chunk_size);
}

static inline uint64_t
get_chunk_count(uint32_t chunk_size, uint64_t file_size)
{
    if (file_size == 0) {
        return 0;
    }
    return (file_size - 1) / chunk_size + 1;
}

static int
write_header(aegis_raf_ctx_internal *ctx)
{
    uint8_t hdr[AEGIS_RAF_HEADER_SIZE];

    memcpy(hdr, AEGIS_RAF_MAGIC, 8);
    STORE16_LE(hdr + 8, AEGIS_RAF_VERSION);
    STORE16_LE(hdr + 10, AEGIS_RAF_HEADER_SIZE);
    STORE32_LE(hdr + 12, ctx->chunk_size);
    STORE16_LE(hdr + 16, AEGIS_RAF_MAC_LEN);
    STORE16_LE(hdr + 18, ctx->alg_id);
    STORE64_LE(hdr + 20, ctx->file_size);
    memcpy(hdr + 28, ctx->file_id, AEGIS_RAF_FILE_ID_BYTES);
    memset(hdr + 60, 0, AEGIS_RAF_RESERVED_BYTES);

    if (compute_header_mac(hdr + AEGIS_RAF_HEADER_SIZE - AEGIS_RAF_TAG_BYTES, hdr, ctx->hdr_key) !=
        0) {
        return -1;
    }

    return ctx->io.write_at(ctx->io.user, hdr, AEGIS_RAF_HEADER_SIZE, 0);
}

static int
read_and_verify_header(aegis_raf_ctx_internal *ctx)
{
    uint8_t        hdr[AEGIS_RAF_HEADER_SIZE];
    uint16_t       version;
    uint16_t       header_size;
    uint16_t       mac_len;
    uint16_t       alg_id;
    const uint8_t *reserved;
    size_t         i;

    if (ctx->io.read_at(ctx->io.user, hdr, AEGIS_RAF_HEADER_SIZE, 0) != 0) {
        return -1;
    }

    if (memcmp(hdr, AEGIS_RAF_MAGIC, 8) != 0) {
        errno = EINVAL;
        return -1;
    }

    version = LOAD16_LE(hdr + 8);
    if (version != AEGIS_RAF_VERSION) {
        errno = EINVAL;
        return -1;
    }

    header_size = LOAD16_LE(hdr + 10);
    if (header_size != AEGIS_RAF_HEADER_SIZE) {
        errno = EINVAL;
        return -1;
    }

    ctx->chunk_size = LOAD32_LE(hdr + 12);
    if (ctx->chunk_size < AEGIS_RAF_CHUNK_MIN || ctx->chunk_size > AEGIS_RAF_CHUNK_MAX ||
        (ctx->chunk_size % 16) != 0) {
        errno = EINVAL;
        return -1;
    }

    mac_len = LOAD16_LE(hdr + 16);
    if (mac_len != AEGIS_RAF_MAC_LEN) {
        errno = EINVAL;
        return -1;
    }

    alg_id = LOAD16_LE(hdr + 18);
    if (alg_id != ALG_ID) {
        errno = EINVAL;
        return -1;
    }

    ctx->file_size = LOAD64_LE(hdr + 20);
    memcpy(ctx->file_id, hdr + 28, AEGIS_RAF_FILE_ID_BYTES);

    reserved = hdr + 60;
    for (i = 0; i < AEGIS_RAF_RESERVED_BYTES; i++) {
        if (reserved[i] != 0) {
            errno = EINVAL;
            return -1;
        }
    }

    if (verify_header_mac(hdr, ctx->hdr_key) != 0) {
        return -1;
    }

    ctx->alg_id = alg_id;
    return 0;
}

size_t
FN(scratch_size)(uint32_t chunk_size)
{
    size_t rec_size    = (size_t) NPUBBYTES + chunk_size + AEGIS_RAF_TAG_BYTES;
    size_t aligned_rec = AEGIS_RAF_ALIGN_UP(rec_size, AEGIS_RAF_SCRATCH_ALIGN);
    size_t aligned_chk = AEGIS_RAF_ALIGN_UP((size_t) chunk_size, AEGIS_RAF_SCRATCH_ALIGN);
    return aligned_rec + aligned_chk;
}

int
FN(scratch_validate)(const aegis_raf_scratch *scratch, uint32_t chunk_size)
{
    size_t required;

    if (chunk_size < AEGIS_RAF_CHUNK_MIN || chunk_size > AEGIS_RAF_CHUNK_MAX ||
        (chunk_size % 16) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (scratch == NULL || scratch->buf == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (((uintptr_t) scratch->buf % AEGIS_RAF_SCRATCH_ALIGN) != 0) {
        errno = EINVAL;
        return -1;
    }
    required = FN(scratch_size)(chunk_size);
    if (scratch->len < required) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int
setup_scratch_buffers(aegis_raf_ctx_internal *ctx, const aegis_raf_scratch *scratch)
{
    size_t rec_size    = (size_t) record_size(ctx->chunk_size);
    size_t aligned_rec = AEGIS_RAF_ALIGN_UP(rec_size, AEGIS_RAF_SCRATCH_ALIGN);

    if (FN(scratch_validate)(scratch, ctx->chunk_size) != 0) {
        return -1;
    }

    ctx->scratch_buf     = scratch->buf;
    ctx->scratch_len     = scratch->len;
    ctx->record_buf      = scratch->buf;
    ctx->record_buf_size = rec_size;
    ctx->chunk_buf       = scratch->buf + aligned_rec;
    ctx->chunk_buf_size  = ctx->chunk_size;

    return 0;
}

static void
zeroize_scratch_buffers(aegis_raf_ctx_internal *ctx)
{
    if (ctx->scratch_buf != NULL && ctx->scratch_len > 0) {
        memset(ctx->scratch_buf, 0, ctx->scratch_len);
    }
    ctx->scratch_buf     = NULL;
    ctx->scratch_len     = 0;
    ctx->record_buf      = NULL;
    ctx->record_buf_size = 0;
    ctx->chunk_buf       = NULL;
    ctx->chunk_buf_size  = 0;
}

static int
setup_merkle_config(aegis_raf_ctx_internal *ctx, const aegis_raf_merkle_config *merkle,
                    uint64_t current_file_size, uint32_t chunk_size)
{
    uint64_t current_chunks;
    uint64_t i;
    int      ret;

    if (merkle == NULL) {
        ctx->merkle_enabled = 0;
        memset(&ctx->merkle_cfg, 0, sizeof(ctx->merkle_cfg));
        return 0;
    }

    if (aegis_raf_merkle_config_validate(merkle) != 0) {
        return -1;
    }

    current_chunks = get_chunk_count(chunk_size, current_file_size);
    if (current_chunks > merkle->max_chunks) {
        errno = EOVERFLOW;
        return -1;
    }

    ctx->merkle_cfg     = *merkle;
    ctx->merkle_enabled = 1;

    for (i = 0; i < merkle->max_chunks; i++) {
        ret = raf_merkle_clear_leaf(&ctx->merkle_cfg, i);
        if (ret != 0) {
            return ret;
        }
    }
    if (merkle->max_chunks > 0) {
        ret = raf_merkle_update_parents(&ctx->merkle_cfg, 0, merkle->max_chunks - 1);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int
read_chunk(aegis_raf_ctx_internal *ctx, uint64_t chunk_idx)
{
    uint64_t off      = get_chunk_offset(ctx->chunk_size, chunk_idx);
    uint64_t rec_size = record_size(ctx->chunk_size);
    uint8_t *record   = ctx->record_buf;
    uint8_t *nonce;
    uint8_t *ciphertext;
    uint8_t *tag;
    uint8_t  aad[AAD_BYTES];
    int      ret;

    if (ctx->io.read_at(ctx->io.user, record, rec_size, off) != 0) {
        return -1;
    }

    nonce      = record;
    ciphertext = record + NPUBBYTES;
    tag        = record + NPUBBYTES + ctx->chunk_size;

    build_aad(aad, ctx->file_id, chunk_idx, ctx->chunk_size);

    ret = VARIANT_decrypt_detached(ctx->chunk_buf, ciphertext, ctx->chunk_size, tag,
                                   AEGIS_RAF_TAG_BYTES, aad, AAD_BYTES, nonce, ctx->enc_key);

    memset(record, 0, rec_size);

    if (ret != 0) {
        errno = EBADMSG;
    }
    return ret;
}

static int
write_chunk(aegis_raf_ctx_internal *ctx, size_t plaintext_len, uint64_t chunk_idx)
{
    uint64_t off      = get_chunk_offset(ctx->chunk_size, chunk_idx);
    uint64_t rec_size = record_size(ctx->chunk_size);
    uint8_t *record   = ctx->record_buf;
    uint8_t *nonce;
    uint8_t *ciphertext;
    uint8_t *tag;
    uint8_t  aad[AAD_BYTES];
    int      ret;

    nonce      = record;
    ciphertext = record + NPUBBYTES;
    tag        = record + NPUBBYTES + ctx->chunk_size;

    if (ctx->rng.random(ctx->rng.user, nonce, NPUBBYTES) != 0) {
        return -1;
    }

    if (plaintext_len < ctx->chunk_size) {
        memset(ctx->chunk_buf + plaintext_len, 0, ctx->chunk_size - plaintext_len);
    }

    build_aad(aad, ctx->file_id, chunk_idx, ctx->chunk_size);

    ret = VARIANT_encrypt_detached(ciphertext, tag, AEGIS_RAF_TAG_BYTES, ctx->chunk_buf,
                                   ctx->chunk_size, aad, AAD_BYTES, nonce, ctx->enc_key);

    if (ret != 0) {
        memset(record, 0, rec_size);
        return -1;
    }

    ret = ctx->io.write_at(ctx->io.user, record, rec_size, off);
    memset(record, 0, rec_size);
    return ret;
}

int
FN(create)(CTX_TYPE *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
           const aegis_raf_config *cfg, const uint8_t *master_key)
{
    uint64_t                backing_size;
    int                     file_exists;
    aegis_raf_ctx_internal *internal;

    if (io == NULL || rng == NULL || cfg == NULL || master_key == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (io->read_at == NULL || io->write_at == NULL || io->get_size == NULL ||
        io->set_size == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (rng->random == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->chunk_size < AEGIS_RAF_CHUNK_MIN || cfg->chunk_size > AEGIS_RAF_CHUNK_MAX ||
        (cfg->chunk_size % 16) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->scratch == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (io->get_size(io->user, &backing_size) != 0) {
        return -1;
    }

    file_exists = (backing_size >= AEGIS_RAF_HEADER_SIZE);

    if (file_exists && !(cfg->flags & AEGIS_RAF_TRUNCATE)) {
        errno = EEXIST;
        return -1;
    }
    if (!file_exists && !(cfg->flags & AEGIS_RAF_CREATE)) {
        errno = ENOENT;
        return -1;
    }

    internal = (aegis_raf_ctx_internal *) ctx;
    COMPILER_ASSERT(sizeof(CTX_TYPE) >= sizeof(aegis_raf_ctx_internal));
    memset(internal, 0, sizeof(aegis_raf_ctx_internal));

    internal->io         = *io;
    internal->rng        = *rng;
    internal->chunk_size = cfg->chunk_size;
    internal->alg_id     = ALG_ID;
    internal->file_size  = 0;
    internal->keybytes   = KEYBYTES;
    internal->npubbytes  = NPUBBYTES;

    if (setup_scratch_buffers(internal, cfg->scratch) != 0) {
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    if (rng->random(rng->user, internal->file_id, AEGIS_RAF_FILE_ID_BYTES) != 0) {
        zeroize_scratch_buffers(internal);
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    derive_keys(internal->enc_key, internal->hdr_key, master_key, internal->file_id);

    if (internal->io.set_size(internal->io.user, AEGIS_RAF_HEADER_SIZE) != 0) {
        zeroize_scratch_buffers(internal);
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    if (write_header(internal) != 0) {
        zeroize_scratch_buffers(internal);
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    if (setup_merkle_config(internal, cfg->merkle, 0, internal->chunk_size) != 0) {
        zeroize_scratch_buffers(internal);
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    return 0;
}

int
FN(open)(CTX_TYPE *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
         const aegis_raf_config *cfg, const uint8_t *master_key)
{
    aegis_raf_ctx_internal *internal;
    uint64_t                backing_size;
    uint64_t                backing_needed;
    uint64_t                max_chunks;
    uint64_t                rec_size;
    uint8_t                 hdr[AEGIS_RAF_HEADER_SIZE];

    if (io == NULL || rng == NULL || cfg == NULL || master_key == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (io->read_at == NULL || io->write_at == NULL || io->get_size == NULL ||
        io->set_size == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (rng->random == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->scratch == NULL) {
        errno = EINVAL;
        return -1;
    }

    internal = (aegis_raf_ctx_internal *) ctx;
    COMPILER_ASSERT(sizeof(CTX_TYPE) >= sizeof(aegis_raf_ctx_internal));
    memset(internal, 0, sizeof(aegis_raf_ctx_internal));

    internal->io        = *io;
    internal->rng       = *rng;
    internal->keybytes  = KEYBYTES;
    internal->npubbytes = NPUBBYTES;

    if (io->get_size(io->user, &backing_size) != 0) {
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }
    if (backing_size < AEGIS_RAF_HEADER_SIZE) {
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        errno = EINVAL;
        return -1;
    }

    if (io->read_at(io->user, hdr, AEGIS_RAF_HEADER_SIZE, 0) != 0) {
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    memcpy(internal->file_id, hdr + 28, AEGIS_RAF_FILE_ID_BYTES);
    derive_keys(internal->enc_key, internal->hdr_key, master_key, internal->file_id);

    if (read_and_verify_header(internal) != 0) {
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }
    rec_size = (uint64_t) record_size(internal->chunk_size);
    max_chunks = get_chunk_count(internal->chunk_size, internal->file_size);
    if (max_chunks != 0 &&
        max_chunks > (UINT64_MAX - AEGIS_RAF_HEADER_SIZE) / rec_size) {
        errno = EOVERFLOW;
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }
    backing_needed = AEGIS_RAF_HEADER_SIZE + max_chunks * rec_size;
    if (backing_size < backing_needed) {
        errno = EINVAL;
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    if (setup_scratch_buffers(internal, cfg->scratch) != 0) {
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    if (setup_merkle_config(internal, cfg->merkle, internal->file_size, internal->chunk_size) !=
        0) {
        zeroize_scratch_buffers(internal);
        memset(internal, 0, sizeof(aegis_raf_ctx_internal));
        return -1;
    }

    return 0;
}

int
FN(read)(CTX_TYPE *ctx, uint8_t *out, size_t *bytes_read, size_t len, uint64_t offset)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;
    size_t                  total_read;
    uint64_t                chunk_idx;
    size_t                  offset_in_chunk;
    size_t                  bytes_to_read;

    *bytes_read = 0;
    if (len == 0 || offset >= internal->file_size) {
        return 0;
    }

    if (len > internal->file_size - offset) {
        len = (size_t) (internal->file_size - offset);
    }

    total_read = 0;
    while (total_read < len) {
        chunk_idx       = (offset + total_read) / internal->chunk_size;
        offset_in_chunk = (offset + total_read) % internal->chunk_size;
        bytes_to_read   = internal->chunk_size - offset_in_chunk;
        if (bytes_to_read > len - total_read) {
            bytes_to_read = len - total_read;
        }

        if (read_chunk(internal, chunk_idx) != 0) {
            return -1;
        }

        memcpy(out + total_read, internal->chunk_buf + offset_in_chunk, bytes_to_read);
        total_read += bytes_to_read;
    }

    *bytes_read = total_read;
    return 0;
}

static int
write_impl(aegis_raf_ctx_internal *internal, size_t *bytes_written, const uint8_t *in, size_t len,
           uint64_t offset)
{
    uint64_t new_file_size;
    uint64_t old_num_chunks;
    uint64_t new_num_chunks;
    uint64_t rec_size;
    uint64_t chunks_size;
    uint64_t new_backing_size;
    uint64_t gap_start;
    uint64_t gap_end;
    uint64_t first_gap_chunk;
    uint64_t last_gap_chunk;
    uint64_t ci;
    uint64_t chunk_start;
    uint64_t chunk_end;
    uint64_t effective_file_size;
    size_t   zero_start;
    size_t   zero_end;
    size_t   total_written;
    uint64_t chunk_idx;
    size_t   offset_in_chunk;
    size_t   bytes_to_write;
    int      need_read_modify_write;
    size_t   chunk_valid_len;
    uint64_t chunk_end_offset;

    *bytes_written = 0;

    if (len > 0 && offset > UINT64_MAX - len) {
        errno = EOVERFLOW;
        return -1;
    }
    new_file_size = offset + len;

    old_num_chunks = get_chunk_count(internal->chunk_size, internal->file_size);
    new_num_chunks = get_chunk_count(internal->chunk_size, new_file_size);
    rec_size       = record_size(internal->chunk_size);

    if (new_num_chunks > UINT64_MAX / rec_size) {
        errno = EOVERFLOW;
        return -1;
    }
    chunks_size = new_num_chunks * rec_size;
    if (chunks_size > UINT64_MAX - AEGIS_RAF_HEADER_SIZE) {
        errno = EOVERFLOW;
        return -1;
    }

    if (internal->merkle_enabled && new_num_chunks > internal->merkle_cfg.max_chunks) {
        errno = EOVERFLOW;
        return -1;
    }

    if (new_file_size > internal->file_size) {
        new_backing_size = AEGIS_RAF_HEADER_SIZE + chunks_size;
        if (internal->io.set_size(internal->io.user, new_backing_size) != 0) {
            return -1;
        }
    }

    if (offset > internal->file_size) {
        gap_start       = internal->file_size;
        gap_end         = offset;
        first_gap_chunk = gap_start / internal->chunk_size;
        last_gap_chunk  = (gap_end > 0) ? (gap_end - 1) / internal->chunk_size : 0;

        for (ci = first_gap_chunk; ci <= last_gap_chunk && ci < new_num_chunks; ci++) {
            chunk_start = ci * internal->chunk_size;
            chunk_end   = chunk_start + internal->chunk_size;

            if (ci < old_num_chunks) {
                if (read_chunk(internal, ci) != 0) {
                    return -1;
                }
            } else {
                memset(internal->chunk_buf, 0, internal->chunk_size);
            }

            zero_start = 0;
            zero_end   = internal->chunk_size;
            if (gap_start > chunk_start) {
                zero_start = (size_t) (gap_start - chunk_start);
            }
            if (gap_end < chunk_end) {
                zero_end = (size_t) (gap_end - chunk_start);
            }
            if (zero_end > zero_start) {
                memset(internal->chunk_buf + zero_start, 0, zero_end - zero_start);
            }

            if (write_chunk(internal, internal->chunk_size, ci) != 0) {
                return -1;
            }

            if (internal->merkle_enabled) {
                if (raf_merkle_update_chunk(&internal->merkle_cfg, internal->chunk_buf,
                                            internal->chunk_size, ci, new_file_size) != 0) {
                    return -1;
                }
            }
        }
    }

    total_written = 0;
    while (total_written < len) {
        chunk_idx       = (offset + total_written) / internal->chunk_size;
        offset_in_chunk = (offset + total_written) % internal->chunk_size;
        bytes_to_write  = internal->chunk_size - offset_in_chunk;
        if (bytes_to_write > len - total_written) {
            bytes_to_write = len - total_written;
        }

        need_read_modify_write = (offset_in_chunk != 0 || bytes_to_write < internal->chunk_size);
        if (need_read_modify_write) {
            chunk_start = chunk_idx * internal->chunk_size;
            if (chunk_start < internal->file_size) {
                if (read_chunk(internal, chunk_idx) != 0) {
                    return -1;
                }
            } else {
                memset(internal->chunk_buf, 0, internal->chunk_size);
            }
        }

        memcpy(internal->chunk_buf + offset_in_chunk, in + total_written, bytes_to_write);

        effective_file_size =
            new_file_size > internal->file_size ? new_file_size : internal->file_size;

        chunk_end_offset = (chunk_idx + 1) * internal->chunk_size;
        if (chunk_end_offset <= effective_file_size) {
            chunk_valid_len = internal->chunk_size;
        } else if (effective_file_size > chunk_idx * internal->chunk_size) {
            chunk_valid_len = (size_t) (effective_file_size - chunk_idx * internal->chunk_size);
        } else {
            chunk_valid_len = offset_in_chunk + bytes_to_write;
        }

        if (write_chunk(internal, chunk_valid_len, chunk_idx) != 0) {
            return -1;
        }

        if (internal->merkle_enabled) {
            if (raf_merkle_update_chunk(&internal->merkle_cfg, internal->chunk_buf, chunk_valid_len,
                                        chunk_idx, effective_file_size) != 0) {
                return -1;
            }
        }

        total_written += bytes_to_write;
    }

    if (new_file_size > internal->file_size) {
        internal->file_size = new_file_size;
        if (write_header(internal) != 0) {
            return -1;
        }
    }

    *bytes_written = total_written;
    return 0;
}

int
FN(write)(CTX_TYPE *ctx, size_t *bytes_written, const uint8_t *in, size_t len, uint64_t offset)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;

    *bytes_written = 0;
    if (len == 0) {
        return 0;
    }

    return write_impl(internal, bytes_written, in, len, offset);
}

int
FN(truncate)(CTX_TYPE *ctx, uint64_t size)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;
    size_t                  written;
    uint64_t                old_num_chunks;
    uint64_t                new_num_chunks;
    uint64_t                rec_size;
    uint64_t                chunks_size;
    uint64_t                new_backing_size;

    if (size == internal->file_size) {
        return 0;
    }

    if (size > internal->file_size) {
        return write_impl(internal, &written, NULL, 0, size);
    }

    old_num_chunks = get_chunk_count(internal->chunk_size, internal->file_size);
    new_num_chunks = get_chunk_count(internal->chunk_size, size);
    rec_size       = record_size(internal->chunk_size);

    if (new_num_chunks > UINT64_MAX / rec_size) {
        errno = EOVERFLOW;
        return -1;
    }
    chunks_size = new_num_chunks * rec_size;
    if (chunks_size > UINT64_MAX - AEGIS_RAF_HEADER_SIZE) {
        errno = EOVERFLOW;
        return -1;
    }
    new_backing_size = AEGIS_RAF_HEADER_SIZE + chunks_size;

    if (internal->io.set_size(internal->io.user, new_backing_size) != 0) {
        return -1;
    }

    if (internal->merkle_enabled && new_num_chunks < old_num_chunks) {
        if (raf_merkle_clear_range(&internal->merkle_cfg, new_num_chunks, old_num_chunks - 1) !=
            0) {
            return -1;
        }
    }

    internal->file_size = size;
    return write_header(internal);
}

int
FN(get_size)(const CTX_TYPE *ctx, uint64_t *size)
{
    const aegis_raf_ctx_internal *internal = (const aegis_raf_ctx_internal *) ctx;
    *size                                  = internal->file_size;
    return 0;
}

int
FN(sync)(CTX_TYPE *ctx)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;
    if (internal->io.sync != NULL) {
        return internal->io.sync(internal->io.user);
    }
    return 0;
}

void
FN(close)(CTX_TYPE *ctx)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;
    if (internal->io.sync != NULL) {
        (void) internal->io.sync(internal->io.user);
    }
    zeroize_scratch_buffers(internal);
    memset(internal, 0, sizeof(aegis_raf_ctx_internal));
}

int
FN(merkle_rebuild)(CTX_TYPE *ctx)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;
    uint64_t                num_chunks;
    uint64_t                ci;
    size_t                  chunk_len;
    uint64_t                chunk_end;
    int                     ret;

    if (!internal->merkle_enabled) {
        errno = EINVAL;
        return -1;
    }

    num_chunks = get_chunk_count(internal->chunk_size, internal->file_size);

    for (ci = 0; ci < num_chunks; ci++) {
        if (read_chunk(internal, ci) != 0) {
            return -1;
        }

        chunk_end = (ci + 1) * internal->chunk_size;
        if (chunk_end <= internal->file_size) {
            chunk_len = internal->chunk_size;
        } else {
            chunk_len = (size_t) (internal->file_size - ci * internal->chunk_size);
        }

        ret = raf_merkle_update_leaf(&internal->merkle_cfg, internal->chunk_buf, chunk_len, ci,
                                     internal->file_size);
        if (ret != 0) {
            return ret;
        }
    }

    for (ci = num_chunks; ci < internal->merkle_cfg.max_chunks; ci++) {
        ret = raf_merkle_clear_leaf(&internal->merkle_cfg, ci);
        if (ret != 0) {
            return ret;
        }
    }

    if (internal->merkle_cfg.max_chunks > 0) {
        ret = raf_merkle_update_parents(&internal->merkle_cfg, 0,
                                        internal->merkle_cfg.max_chunks - 1);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

int
FN(merkle_verify)(CTX_TYPE *ctx, uint64_t *corrupted_chunk)
{
    aegis_raf_ctx_internal *internal = (aegis_raf_ctx_internal *) ctx;
    uint64_t                num_chunks;
    uint64_t                ci;
    size_t                  chunk_len;
    uint64_t                chunk_end;
    uint8_t                 computed_hash[256];
    size_t                  leaf_off;
    int                     ret;

    if (!internal->merkle_enabled) {
        errno = ENOTSUP;
        return -1;
    }

    if (internal->merkle_cfg.hash_len > sizeof(computed_hash)) {
        errno = EINVAL;
        return -1;
    }

    num_chunks = get_chunk_count(internal->chunk_size, internal->file_size);

    for (ci = 0; ci < num_chunks; ci++) {
        if (read_chunk(internal, ci) != 0) {
            if (corrupted_chunk != NULL) {
                *corrupted_chunk = ci;
            }
            return -1;
        }

        chunk_end = (ci + 1) * internal->chunk_size;
        if (chunk_end <= internal->file_size) {
            chunk_len = internal->chunk_size;
        } else {
            chunk_len = (size_t) (internal->file_size - ci * internal->chunk_size);
        }

        ret = internal->merkle_cfg.hash_leaf(internal->merkle_cfg.user, computed_hash,
                                             internal->merkle_cfg.hash_len, internal->chunk_buf,
                                             chunk_len, ci, internal->file_size);
        if (ret != 0) {
            if (corrupted_chunk != NULL) {
                *corrupted_chunk = ci;
            }
            return -1;
        }

        leaf_off = (size_t) (ci * internal->merkle_cfg.hash_len);
        if (memcmp(computed_hash, internal->merkle_cfg.buf + leaf_off,
                   internal->merkle_cfg.hash_len) != 0) {
            if (corrupted_chunk != NULL) {
                *corrupted_chunk = ci;
            }
            errno = EBADMSG;
            return -1;
        }
    }

    return 0;
}

#undef CONCAT_
#undef CONCAT
#undef CONCAT3_
#undef CONCAT3
#undef FN
#undef CTX_TYPE
#undef MAC_STATE_TYPE
#undef AAD_BYTES
#undef KDF_CONST
#undef KDF_CONST_LEN
