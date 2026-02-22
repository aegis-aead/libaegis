#ifndef raf_merkle_H
#define raf_merkle_H

#include <stddef.h>
#include <stdint.h>

#include "../include/aegis_raf.h"

/*
 * Internal Merkle tree helpers for RAF.
 *
 * The Merkle buffer stores nodes level by level:
 *   Level 0: max_chunks leaves (one per chunk)
 *   Level 1: ceil(max_chunks / 2) nodes
 *   ...
 *   Level L-1: 1 node (root)
 *
 * Each node is hash_len bytes. Levels are stored consecutively without padding.
 */

/*
 * Returns the number of nodes at the given level for a tree with max_chunks leaves.
 * Level 0 has max_chunks nodes; each subsequent level has ceil(prev / 2).
 */
uint64_t raf_merkle_level_node_count(uint64_t max_chunks, uint32_t level);

/*
 * Returns the byte offset of the start of the given level within the buffer.
 */
size_t raf_merkle_level_offset(uint64_t max_chunks, uint32_t hash_len, uint32_t level);

/*
 * Returns the byte offset of a specific node within the buffer.
 * node_idx is relative to the start of the level.
 */
size_t raf_merkle_node_offset(uint64_t max_chunks, uint32_t hash_len, uint32_t level,
                              uint64_t node_idx);

/*
 * Update a single leaf hash. Computes hash_leaf for the given chunk data and
 * stores it at the appropriate position in the buffer.
 *
 * chunk_data:    Plaintext chunk contents (may be less than chunk_size for final chunk).
 * chunk_len:     Actual length of chunk data (plaintext bytes in this chunk).
 * chunk_idx:     Index of the chunk (0-based).
 * cfg:           Merkle configuration with buffer and callbacks.
 *
 * Returns 0 on success, -1 on error.
 */
int raf_merkle_update_leaf(const aegis_raf_merkle_config *cfg, const uint8_t *chunk_data,
                           size_t chunk_len, uint64_t chunk_idx);

/*
 * Mark a leaf as empty. Computes hash_empty for the given chunk index and
 * stores it at the appropriate position in the buffer.
 *
 * chunk_idx:     Index of the chunk to mark as empty.
 * cfg:           Merkle configuration with buffer and callbacks.
 *
 * Returns 0 on success, -1 on error.
 */
int raf_merkle_clear_leaf(const aegis_raf_merkle_config *cfg, uint64_t chunk_idx);

/*
 * Update parents from the given range of leaves up to the root.
 * Call this after updating one or more consecutive leaves.
 *
 * first_chunk:   First leaf index in the updated range.
 * last_chunk:    Last leaf index in the updated range (inclusive).
 * cfg:           Merkle configuration with buffer and callbacks.
 *
 * Returns 0 on success, -1 on error.
 */
int raf_merkle_update_parents(const aegis_raf_merkle_config *cfg, uint64_t first_chunk,
                              uint64_t last_chunk);

/*
 * Update a single leaf and propagate changes to the root.
 * Convenience wrapper that calls update_leaf then update_parents.
 *
 * Returns 0 on success, -1 on error.
 */
int raf_merkle_update_chunk(const aegis_raf_merkle_config *cfg, const uint8_t *chunk_data,
                            size_t chunk_len, uint64_t chunk_idx);

/*
 * Clear a range of leaves (mark as empty) and propagate changes to the root.
 * Used when shrinking a file to invalidate leaves beyond the new EOF.
 *
 * first_chunk:   First leaf index to clear.
 * last_chunk:    Last leaf index to clear (inclusive).
 * cfg:           Merkle configuration with buffer and callbacks.
 *
 * Returns 0 on success, -1 on error.
 */
int raf_merkle_clear_range(const aegis_raf_merkle_config *cfg, uint64_t first_chunk,
                           uint64_t last_chunk);

/*
 * Validate a Merkle configuration. Returns 0 if valid, -1 with errno set if not.
 * Checks that buf is non-NULL, hash_len > 0, max_chunks > 0, all callbacks are
 * provided, and the buffer is large enough.
 */
int aegis_raf_merkle_config_validate(const aegis_raf_merkle_config *cfg);

#endif
