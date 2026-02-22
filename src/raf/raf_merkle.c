#include <string.h>

#include "raf_internal.h"
#include "raf_merkle.h"

uint64_t
raf_merkle_level_node_count(uint64_t max_chunks, uint32_t level)
{
    uint64_t count = max_chunks;
    uint32_t i = 0;

    if (max_chunks == 0) {
        return 0;
    }

    while (1) {
        if (i == level) {
            return count;
        }
        if (count <= 1) {
            return 0;
        }
        count = (count + 1) / 2;
        i++;
    }
}

static uint32_t
aegis_raf_merkle_level_count(const aegis_raf_merkle_config *cfg)
{
    uint32_t levels = 0;
    uint64_t count;

    if (cfg == NULL || cfg->max_chunks == 0) {
        return 0;
    }

    count = cfg->max_chunks;
    while (count > 0) {
        levels++;
        if (count == 1) {
            break;
        }
        count = (count + 1) / 2;
    }

    return levels;
}

size_t
aegis_raf_merkle_buffer_size(const aegis_raf_merkle_config *cfg)
{
    uint64_t total_nodes = 0;
    uint64_t count;
    uint64_t size;

    if (cfg == NULL || cfg->max_chunks == 0 || cfg->hash_len == 0) {
        return 0;
    }

    count = cfg->max_chunks;
    while (count > 0) {
        if (total_nodes > UINT64_MAX - count) {
            return SIZE_MAX;
        }
        total_nodes += count;
        if (count == 1) {
            break;
        }
        count = (count + 1) / 2;
    }

    if (total_nodes > SIZE_MAX / cfg->hash_len) {
        return SIZE_MAX;
    }
    size = total_nodes * cfg->hash_len;
    if (size > SIZE_MAX) {
        return SIZE_MAX;
    }

    return (size_t) size;
}

size_t
raf_merkle_level_offset(uint64_t max_chunks, uint32_t hash_len, uint32_t level)
{
    size_t   offset = 0;
    uint64_t count  = max_chunks;
    uint32_t i;

    if (max_chunks == 0 || hash_len == 0) {
        return 0;
    }

    for (i = 0; i < level && count > 0; i++) {
        offset += (size_t) (count * hash_len);
        if (count == 1) {
            break;
        }
        count = (count + 1) / 2;
    }

    return offset;
}

size_t
raf_merkle_node_offset(uint64_t max_chunks, uint32_t hash_len, uint32_t level, uint64_t node_idx)
{
    size_t level_off = raf_merkle_level_offset(max_chunks, hash_len, level);
    return level_off + (size_t) (node_idx * hash_len);
}

static size_t
aegis_raf_merkle_leaf_offset(const aegis_raf_merkle_config *cfg, uint64_t chunk_idx)
{
    if (cfg == NULL || chunk_idx >= cfg->max_chunks) {
        return 0;
    }
    return (size_t) (chunk_idx * cfg->hash_len);
}

int
aegis_raf_merkle_root(const aegis_raf_merkle_config *cfg,
                      uint8_t *out, size_t out_len,
                      const uint8_t *ctx, size_t ctx_len,
                      uint64_t file_size)
{
    uint32_t       levels;
    size_t         root_offset;
    const uint8_t *structural_root;

    if (cfg == NULL || cfg->buf == NULL || cfg->max_chunks == 0) {
        errno = EINVAL;
        return -1;
    }
    if (out == NULL || out_len < cfg->hash_len) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->hash_commitment == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (ctx == NULL && ctx_len > 0) {
        errno = EINVAL;
        return -1;
    }
    if (ctx_len == 0) {
        ctx = NULL;
    }

    levels          = aegis_raf_merkle_level_count(cfg);
    root_offset     = raf_merkle_level_offset(cfg->max_chunks, cfg->hash_len, levels - 1);
    structural_root = cfg->buf + root_offset;

    return cfg->hash_commitment(cfg->user, out, cfg->hash_len,
                                structural_root, ctx, ctx_len, file_size);
}

int
aegis_raf_merkle_config_validate(const aegis_raf_merkle_config *cfg)
{
    size_t required;

    if (cfg == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (cfg->buf == NULL || cfg->max_chunks == 0) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->hash_len < AEGIS_RAF_MERKLE_HASH_MIN ||
        cfg->hash_len > AEGIS_RAF_MERKLE_HASH_MAX) {
        errno = EINVAL;
        return -1;
    }

    if (cfg->hash_leaf == NULL || cfg->hash_parent == NULL || cfg->hash_empty == NULL ||
        cfg->hash_commitment == NULL) {
        errno = EINVAL;
        return -1;
    }

    required = aegis_raf_merkle_buffer_size(cfg);
    if (required == SIZE_MAX || cfg->len < required) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int
raf_merkle_update_leaf(const aegis_raf_merkle_config *cfg, const uint8_t *chunk_data,
                       size_t chunk_len, uint64_t chunk_idx)
{
    size_t leaf_off;

    if (cfg == NULL || chunk_idx >= cfg->max_chunks) {
        errno = EINVAL;
        return -1;
    }

    leaf_off = aegis_raf_merkle_leaf_offset(cfg, chunk_idx);

    return cfg->hash_leaf(cfg->user, cfg->buf + leaf_off, cfg->hash_len, chunk_data, chunk_len,
                          chunk_idx);
}

int
raf_merkle_clear_leaf(const aegis_raf_merkle_config *cfg, uint64_t chunk_idx)
{
    size_t leaf_off;

    if (cfg == NULL || chunk_idx >= cfg->max_chunks) {
        errno = EINVAL;
        return -1;
    }

    leaf_off = aegis_raf_merkle_leaf_offset(cfg, chunk_idx);

    return cfg->hash_empty(cfg->user, cfg->buf + leaf_off, cfg->hash_len, 0, chunk_idx);
}

int
raf_merkle_update_parents(const aegis_raf_merkle_config *cfg, uint64_t first_chunk,
                          uint64_t last_chunk)
{
    uint32_t levels;
    uint32_t level;
    uint64_t first_idx;
    uint64_t last_idx;
    uint64_t level_count;
    uint64_t i;
    size_t   left_off;
    size_t   right_off;
    size_t   parent_off;
    uint8_t  empty_hash[AEGIS_RAF_MERKLE_HASH_MAX];
    int      ret;

    if (cfg == NULL || first_chunk > last_chunk || last_chunk >= cfg->max_chunks) {
        errno = EINVAL;
        return -1;
    }

    levels = aegis_raf_merkle_level_count(cfg);
    if (levels <= 1) {
        return 0;
    }

    first_idx = first_chunk;
    last_idx  = last_chunk;

    for (level = 0; level < levels - 1; level++) {
        level_count = raf_merkle_level_node_count(cfg->max_chunks, level);

        first_idx = first_idx / 2;
        last_idx  = last_idx / 2;

        for (i = first_idx; i <= last_idx; i++) {
            uint64_t left_child  = i * 2;
            uint64_t right_child = i * 2 + 1;

            left_off = raf_merkle_node_offset(cfg->max_chunks, cfg->hash_len, level, left_child);

            if (right_child < level_count) {
                right_off =
                    raf_merkle_node_offset(cfg->max_chunks, cfg->hash_len, level, right_child);

                parent_off = raf_merkle_node_offset(cfg->max_chunks, cfg->hash_len, level + 1, i);

                ret = cfg->hash_parent(cfg->user, cfg->buf + parent_off, cfg->hash_len,
                                       cfg->buf + left_off, cfg->buf + right_off, level, i);
            } else {
                ret = cfg->hash_empty(cfg->user, empty_hash, cfg->hash_len, level, right_child);
                if (ret != 0) {
                    return ret;
                }

                parent_off = raf_merkle_node_offset(cfg->max_chunks, cfg->hash_len, level + 1, i);

                ret = cfg->hash_parent(cfg->user, cfg->buf + parent_off, cfg->hash_len,
                                       cfg->buf + left_off, empty_hash, level, i);
            }

            if (ret != 0) {
                return ret;
            }
        }
    }

    return 0;
}

int
raf_merkle_update_chunk(const aegis_raf_merkle_config *cfg, const uint8_t *chunk_data,
                        size_t chunk_len, uint64_t chunk_idx)
{
    int ret;

    ret = raf_merkle_update_leaf(cfg, chunk_data, chunk_len, chunk_idx);
    if (ret != 0) {
        return ret;
    }

    return raf_merkle_update_parents(cfg, chunk_idx, chunk_idx);
}

int
raf_merkle_clear_range(const aegis_raf_merkle_config *cfg, uint64_t first_chunk,
                       uint64_t last_chunk)
{
    uint64_t i;
    int      ret;

    if (cfg == NULL || first_chunk > last_chunk || last_chunk >= cfg->max_chunks) {
        errno = EINVAL;
        return -1;
    }

    for (i = first_chunk; i <= last_chunk; i++) {
        ret = raf_merkle_clear_leaf(cfg, i);
        if (ret != 0) {
            return ret;
        }
    }

    return raf_merkle_update_parents(cfg, first_chunk, last_chunk);
}
