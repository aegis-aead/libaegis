#ifndef aegis_raf_H
#define aegis_raf_H

#include <stddef.h>
#include <stdint.h>

#ifndef CRYPTO_ALIGN
#    if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#        define CRYPTO_ALIGN(x) __declspec(align(x))
#    else
#        define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AEGIS_RAF_ALG_128L  1
#define AEGIS_RAF_ALG_128X2 2
#define AEGIS_RAF_ALG_128X4 3
#define AEGIS_RAF_ALG_256   4
#define AEGIS_RAF_ALG_256X2 5
#define AEGIS_RAF_ALG_256X4 6

#define AEGIS_RAF_CREATE   0x01
#define AEGIS_RAF_TRUNCATE 0x02

#define AEGIS_RAF_CHUNK_MIN 1024
#define AEGIS_RAF_CHUNK_MAX (1 << 20)

#define AEGIS_RAF_HEADER_SIZE   92
#define AEGIS_RAF_FILE_ID_BYTES 32
#define AEGIS_RAF_TAG_BYTES     16

#define AEGIS_RAF_SCRATCH_ALIGN  64
#define AEGIS_RAF_ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((size_t) (a) - 1))

#define AEGIS128L_RAF_NPUBBYTES  16
#define AEGIS128X2_RAF_NPUBBYTES 16
#define AEGIS128X4_RAF_NPUBBYTES 16
#define AEGIS256_RAF_NPUBBYTES   32
#define AEGIS256X2_RAF_NPUBBYTES 32
#define AEGIS256X4_RAF_NPUBBYTES 32

#define AEGIS128L_RAF_RECORD_SIZE(chunk_size) \
    ((size_t) (AEGIS128L_RAF_NPUBBYTES) + (size_t) (chunk_size) + (size_t) (AEGIS_RAF_TAG_BYTES))

#define AEGIS128X2_RAF_RECORD_SIZE(chunk_size) \
    ((size_t) (AEGIS128X2_RAF_NPUBBYTES) + (size_t) (chunk_size) + (size_t) (AEGIS_RAF_TAG_BYTES))

#define AEGIS128X4_RAF_RECORD_SIZE(chunk_size) \
    ((size_t) (AEGIS128X4_RAF_NPUBBYTES) + (size_t) (chunk_size) + (size_t) (AEGIS_RAF_TAG_BYTES))

#define AEGIS256_RAF_RECORD_SIZE(chunk_size) \
    ((size_t) (AEGIS256_RAF_NPUBBYTES) + (size_t) (chunk_size) + (size_t) (AEGIS_RAF_TAG_BYTES))

#define AEGIS256X2_RAF_RECORD_SIZE(chunk_size) \
    ((size_t) (AEGIS256X2_RAF_NPUBBYTES) + (size_t) (chunk_size) + (size_t) (AEGIS_RAF_TAG_BYTES))

#define AEGIS256X4_RAF_RECORD_SIZE(chunk_size) \
    ((size_t) (AEGIS256X4_RAF_NPUBBYTES) + (size_t) (chunk_size) + (size_t) (AEGIS_RAF_TAG_BYTES))

#define AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)                                            \
    (AEGIS_RAF_ALIGN_UP(AEGIS128L_RAF_RECORD_SIZE(chunk_size), AEGIS_RAF_SCRATCH_ALIGN) + \
     AEGIS_RAF_ALIGN_UP((size_t) (chunk_size), AEGIS_RAF_SCRATCH_ALIGN))

#define AEGIS128X2_RAF_SCRATCH_SIZE(chunk_size)                                            \
    (AEGIS_RAF_ALIGN_UP(AEGIS128X2_RAF_RECORD_SIZE(chunk_size), AEGIS_RAF_SCRATCH_ALIGN) + \
     AEGIS_RAF_ALIGN_UP((size_t) (chunk_size), AEGIS_RAF_SCRATCH_ALIGN))

#define AEGIS128X4_RAF_SCRATCH_SIZE(chunk_size)                                            \
    (AEGIS_RAF_ALIGN_UP(AEGIS128X4_RAF_RECORD_SIZE(chunk_size), AEGIS_RAF_SCRATCH_ALIGN) + \
     AEGIS_RAF_ALIGN_UP((size_t) (chunk_size), AEGIS_RAF_SCRATCH_ALIGN))

#define AEGIS256_RAF_SCRATCH_SIZE(chunk_size)                                            \
    (AEGIS_RAF_ALIGN_UP(AEGIS256_RAF_RECORD_SIZE(chunk_size), AEGIS_RAF_SCRATCH_ALIGN) + \
     AEGIS_RAF_ALIGN_UP((size_t) (chunk_size), AEGIS_RAF_SCRATCH_ALIGN))

#define AEGIS256X2_RAF_SCRATCH_SIZE(chunk_size)                                            \
    (AEGIS_RAF_ALIGN_UP(AEGIS256X2_RAF_RECORD_SIZE(chunk_size), AEGIS_RAF_SCRATCH_ALIGN) + \
     AEGIS_RAF_ALIGN_UP((size_t) (chunk_size), AEGIS_RAF_SCRATCH_ALIGN))

#define AEGIS256X4_RAF_SCRATCH_SIZE(chunk_size)                                            \
    (AEGIS_RAF_ALIGN_UP(AEGIS256X4_RAF_RECORD_SIZE(chunk_size), AEGIS_RAF_SCRATCH_ALIGN) + \
     AEGIS_RAF_ALIGN_UP((size_t) (chunk_size), AEGIS_RAF_SCRATCH_ALIGN))

/*
 * Scratch buffer for RAF operations. Must be allocated by the caller and
 * passed to create/open. Use the *_raf_scratch_size() macros or functions
 * to determine the required size for a given chunk_size.
 */
typedef struct aegis_raf_scratch {
    uint8_t *buf;
    size_t   len;
} aegis_raf_scratch;

/*
 * I/O callbacks for backing store operations. All callbacks receive the
 * user pointer and return 0 on success, -1 on error (with errno set).
 *
 * read_at:  Read exactly len bytes at offset. Returns -1 if fewer available.
 * write_at: Write exactly len bytes at offset.
 * get_size: Get current backing store size in bytes.
 * set_size: Resize backing store (truncate or extend).
 * sync:     Flush writes to durable storage (may be NULL).
 */
typedef struct aegis_raf_io {
    void *user;
    int (*read_at)(void *user, uint8_t *buf, size_t len, uint64_t off);
    int (*write_at)(void *user, const uint8_t *buf, size_t len, uint64_t off);
    int (*get_size)(void *user, uint64_t *size);
    int (*set_size)(void *user, uint64_t size);
    int (*sync)(void *user);
} aegis_raf_io;

/*
 * Random number generator callback for nonce generation.
 * Must provide cryptographically secure random bytes.
 * Returns 0 on success, -1 on error.
 */
typedef struct aegis_raf_rng {
    void *user;
    int (*random)(void *user, uint8_t *out, size_t len);
} aegis_raf_rng;

/*
 * Optional Merkle tree configuration for chunk-level integrity tracking.
 *
 * When provided, the RAF context will automatically update a Merkle tree
 * buffer on chunk writes. The tree root can be used to verify file integrity
 * without reading all chunks.
 *
 * buf:         Caller-allocated buffer for the Merkle tree. Use
 *              aegis_raf_merkle_buffer_size() to determine required size.
 * len:         Size of the buffer in bytes.
 * hash_len:    Size of each hash in bytes (e.g., 32 for SHA-256).
 * max_chunks:  Maximum number of chunks (leaves) the tree can hold.
 *              Writes exceeding this limit will fail with EOVERFLOW.
 * user:        User-defined pointer passed to hash callbacks.
 *
 * Hash callbacks must return 0 on success, -1 on error.
 *
 * hash_leaf:   Hash a chunk. Called with the plaintext chunk data, its length
 *              (may be less than chunk_size for the final chunk), the chunk
 *              index, and the current file size for domain separation.
 *
 * hash_parent: Hash two child nodes to produce a parent. Called with left and
 *              right child hashes, the tree level (0 = leaves), and the node
 *              index within that level.
 *
 * hash_empty:  Produce a hash for an empty/missing node. Called for leaves
 *              beyond EOF and for missing siblings when a level has an odd
 *              number of nodes. Level and node index are provided for domain
 *              separation.
 *
 * Thread Safety: Merkle buffers are not internally synchronized. Callers must
 * serialize writes that share a Merkle buffer, or provide external locking.
 */
typedef struct aegis_raf_merkle_config {
    uint8_t *buf;
    size_t   len;
    uint32_t hash_len;
    uint64_t max_chunks;
    void    *user;

    int (*hash_leaf)(void *user, uint8_t *out, size_t out_len, const uint8_t *chunk,
                     size_t chunk_len, uint64_t chunk_idx, uint64_t file_size);

    int (*hash_parent)(void *user, uint8_t *out, size_t out_len, const uint8_t *left,
                       const uint8_t *right, uint32_t level, uint64_t node_idx);

    int (*hash_empty)(void *user, uint8_t *out, size_t out_len, uint32_t level, uint64_t node_idx);
} aegis_raf_merkle_config;

/*
 * Configuration for RAF create/open operations.
 *
 * scratch:    Caller-allocated scratch buffer (required).
 * chunk_size: Plaintext bytes per chunk (AEGIS_RAF_CHUNK_MIN to AEGIS_RAF_CHUNK_MAX).
 *             Ignored when opening existing files.
 * flags:      AEGIS_RAF_CREATE to create new files, AEGIS_RAF_TRUNCATE to
 *             overwrite existing files.
 * merkle:     Optional Merkle tree configuration. Set to NULL to disable.
 */
typedef struct aegis_raf_config {
    const aegis_raf_scratch       *scratch;
    const aegis_raf_merkle_config *merkle;
    uint32_t                       chunk_size;
    uint8_t                        flags;
} aegis_raf_config;

/*
 * File metadata returned by aegis_raf_probe().
 *
 * alg_id:     Algorithm identifier (AEGIS_RAF_ALG_*).
 * chunk_size: Plaintext bytes per chunk.
 * file_size:  Logical plaintext file size.
 */
typedef struct aegis_raf_info {
    uint16_t alg_id;
    uint32_t chunk_size;
    uint64_t file_size;
} aegis_raf_info;

/* Returns minimum allowed chunk size (AEGIS_RAF_CHUNK_MIN). */
size_t aegis_raf_chunk_min(void);

/* Returns maximum allowed chunk size (AEGIS_RAF_CHUNK_MAX). */
size_t aegis_raf_chunk_max(void);

/* Returns RAF header size in bytes (AEGIS_RAF_HEADER_SIZE). */
size_t aegis_raf_header_size(void);

/* Returns required alignment for scratch buffers (AEGIS_RAF_SCRATCH_ALIGN). */
size_t aegis_raf_scratch_align(void);

/*
 * Probe an encrypted file to determine its algorithm and parameters.
 * Reads and parses the header without validating the MAC.
 * Returns 0 on success, -1 on error (invalid header or I/O failure).
 */
int aegis_raf_probe(const aegis_raf_io *io, aegis_raf_info *info);

/*
 * Scratch buffer helpers.
 *
 * *_raf_scratch_size():     Returns required scratch buffer size for a given
 *                           chunk_size. Use this to allocate the buffer.
 *
 * *_raf_scratch_validate(): Validates that a scratch buffer is large enough
 *                           and properly aligned. Returns 0 if valid, -1 if not.
 */

size_t aegis128l_raf_scratch_size(uint32_t chunk_size);
int    aegis128l_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);

size_t aegis128x2_raf_scratch_size(uint32_t chunk_size);
int    aegis128x2_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);

size_t aegis128x4_raf_scratch_size(uint32_t chunk_size);
int    aegis128x4_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);

size_t aegis256_raf_scratch_size(uint32_t chunk_size);
int    aegis256_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);

size_t aegis256x2_raf_scratch_size(uint32_t chunk_size);
int    aegis256x2_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);

size_t aegis256x4_raf_scratch_size(uint32_t chunk_size);
int    aegis256x4_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);

/*
 * Merkle tree helpers.
 */

/*
 * Returns the required buffer size in bytes for a Merkle tree based on the
 * max_chunks and hash_len fields in the config. The buf field may be NULL
 * when calling this function (it's used to determine how much to allocate).
 * Returns 0 if cfg is NULL, max_chunks is 0, or hash_len is 0.
 */
size_t aegis_raf_merkle_buffer_size(const aegis_raf_merkle_config *cfg);

/*
 * Returns a pointer to the Merkle root hash within the buffer.
 * Returns NULL if cfg is NULL or max_chunks is 0.
 */
const uint8_t *aegis_raf_merkle_root(const aegis_raf_merkle_config *cfg);

/*
 * Random-Access Encrypted File API
 *
 * Provides pread/pwrite-style access to encrypted files. Files are divided
 * into fixed-size chunks, each independently encrypted with a fresh nonce.
 * The API supports multiple AEGIS variants with identical calling conventions.
 *
 * The master_key size depends on the variant:
 *   - AEGIS-128L, AEGIS-128X2, AEGIS-128X4: 16 bytes
 *   - AEGIS-256, AEGIS-256X2, AEGIS-256X4:  32 bytes
 *
 * All functions return 0 on success and -1 on error with errno set.
 */

/* Opaque context for AEGIS-128L RAF operations. */
typedef struct aegis128l_raf_ctx {
    CRYPTO_ALIGN(32) uint8_t opaque[512];
} aegis128l_raf_ctx;

/*
 * Create a new encrypted file.
 *
 * Writes the header and initializes the context for subsequent I/O.
 * Requires AEGIS_RAF_CREATE flag. Use AEGIS_RAF_TRUNCATE to overwrite
 * existing files, otherwise returns -1 with errno=EEXIST.
 *
 * The master_key must be 16 bytes for AEGIS-128L.
 */
int aegis128l_raf_create(aegis128l_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                         const aegis_raf_config *cfg, const uint8_t *master_key);

/*
 * Open an existing encrypted file.
 *
 * Reads and validates the header, verifying the MAC with the provided key.
 * Returns -1 with errno=ENOENT if the file doesn't exist or errno=EINVAL
 * if the header is invalid or the MAC verification fails.
 *
 * The scratch buffer must be sized for the file's chunk_size (from probe).
 */
int aegis128l_raf_open(aegis128l_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                       const aegis_raf_config *cfg, const uint8_t *master_key);

/*
 * Read and decrypt bytes at the given offset.
 *
 * On success, returns 0 and sets *bytes_read to the number of bytes read.
 * Returns 0 with *bytes_read=0 at EOF. Returns -1 on I/O error or if
 * authentication fails (indicating corruption or tampering).
 */
int aegis128l_raf_read(aegis128l_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                       uint64_t offset) __attribute__((warn_unused_result));

/*
 * Encrypt and write bytes at the given offset.
 *
 * Performs read-modify-write for partial chunks. Automatically extends
 * the file when writing past the current end. On success, returns 0 and
 * sets *bytes_written to len.
 */
int aegis128l_raf_write(aegis128l_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                        size_t len, uint64_t offset) __attribute__((warn_unused_result));

/*
 * Resize the file to the given size.
 *
 * Shrinking discards data beyond the new size. Growing fills the new
 * range with zeros (sparse if the backing store supports it).
 */
int aegis128l_raf_truncate(aegis128l_raf_ctx *ctx, uint64_t size);

/* Get the logical plaintext file size. */
int aegis128l_raf_get_size(const aegis128l_raf_ctx *ctx, uint64_t *size);

/* Flush writes to backing store. Calls io->sync if provided. */
int aegis128l_raf_sync(aegis128l_raf_ctx *ctx);

/*
 * Close the context and zeroize all key material.
 * Automatically calls sync before cleanup.
 */
void aegis128l_raf_close(aegis128l_raf_ctx *ctx);

/*
 * Rebuild the Merkle tree from file contents.
 *
 * Reads each chunk from the file and recomputes all leaf and parent hashes.
 * Useful after opening an existing file to restore the Merkle tree state.
 * Returns -1 if Merkle is not enabled or on I/O/hash error.
 */
int aegis128l_raf_merkle_rebuild(aegis128l_raf_ctx *ctx);

/*
 * Verify file integrity against the Merkle tree.
 *
 * Reads each chunk, computes its hash, and compares against the stored tree.
 * On success, returns 0. On corruption, returns -1 and sets *corrupted_chunk
 * to the index of the first corrupted chunk (if corrupted_chunk is not NULL).
 * Returns -1 with errno=ENOTSUP if Merkle is not enabled.
 */
int aegis128l_raf_merkle_verify(aegis128l_raf_ctx *ctx, uint64_t *corrupted_chunk);

/* Opaque context for AEGIS-128X2 RAF operations. See aegis128l_raf_* for API docs. */
typedef struct aegis128x2_raf_ctx {
    CRYPTO_ALIGN(32) uint8_t opaque[512];
} aegis128x2_raf_ctx;

int aegis128x2_raf_create(aegis128x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis128x2_raf_open(aegis128x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis128x2_raf_read(aegis128x2_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                        uint64_t offset) __attribute__((warn_unused_result));

int aegis128x2_raf_write(aegis128x2_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                         size_t len, uint64_t offset) __attribute__((warn_unused_result));

int aegis128x2_raf_truncate(aegis128x2_raf_ctx *ctx, uint64_t size);

int aegis128x2_raf_get_size(const aegis128x2_raf_ctx *ctx, uint64_t *size);

int aegis128x2_raf_sync(aegis128x2_raf_ctx *ctx);

void aegis128x2_raf_close(aegis128x2_raf_ctx *ctx);

int aegis128x2_raf_merkle_rebuild(aegis128x2_raf_ctx *ctx);

int aegis128x2_raf_merkle_verify(aegis128x2_raf_ctx *ctx, uint64_t *corrupted_chunk);

/* Opaque context for AEGIS-128X4 RAF operations. See aegis128l_raf_* for API docs. */
typedef struct aegis128x4_raf_ctx {
    CRYPTO_ALIGN(64) uint8_t opaque[512];
} aegis128x4_raf_ctx;

int aegis128x4_raf_create(aegis128x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis128x4_raf_open(aegis128x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis128x4_raf_read(aegis128x4_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                        uint64_t offset) __attribute__((warn_unused_result));

int aegis128x4_raf_write(aegis128x4_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                         size_t len, uint64_t offset) __attribute__((warn_unused_result));

int aegis128x4_raf_truncate(aegis128x4_raf_ctx *ctx, uint64_t size);

int aegis128x4_raf_get_size(const aegis128x4_raf_ctx *ctx, uint64_t *size);

int aegis128x4_raf_sync(aegis128x4_raf_ctx *ctx);

void aegis128x4_raf_close(aegis128x4_raf_ctx *ctx);

int aegis128x4_raf_merkle_rebuild(aegis128x4_raf_ctx *ctx);

int aegis128x4_raf_merkle_verify(aegis128x4_raf_ctx *ctx, uint64_t *corrupted_chunk);

/* Opaque context for AEGIS-256 RAF operations. Master key is 32 bytes. */
typedef struct aegis256_raf_ctx {
    CRYPTO_ALIGN(16) uint8_t opaque[512];
} aegis256_raf_ctx;

int aegis256_raf_create(aegis256_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis256_raf_open(aegis256_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                      const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis256_raf_read(aegis256_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                      uint64_t offset) __attribute__((warn_unused_result));

int aegis256_raf_write(aegis256_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in, size_t len,
                       uint64_t offset) __attribute__((warn_unused_result));

int aegis256_raf_truncate(aegis256_raf_ctx *ctx, uint64_t size);

int aegis256_raf_get_size(const aegis256_raf_ctx *ctx, uint64_t *size);

int aegis256_raf_sync(aegis256_raf_ctx *ctx);

void aegis256_raf_close(aegis256_raf_ctx *ctx);

int aegis256_raf_merkle_rebuild(aegis256_raf_ctx *ctx);

int aegis256_raf_merkle_verify(aegis256_raf_ctx *ctx, uint64_t *corrupted_chunk);

/* Opaque context for AEGIS-256X2 RAF operations. Master key is 32 bytes. */
typedef struct aegis256x2_raf_ctx {
    CRYPTO_ALIGN(32) uint8_t opaque[512];
} aegis256x2_raf_ctx;

int aegis256x2_raf_create(aegis256x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis256x2_raf_open(aegis256x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis256x2_raf_read(aegis256x2_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                        uint64_t offset) __attribute__((warn_unused_result));

int aegis256x2_raf_write(aegis256x2_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                         size_t len, uint64_t offset) __attribute__((warn_unused_result));

int aegis256x2_raf_truncate(aegis256x2_raf_ctx *ctx, uint64_t size);

int aegis256x2_raf_get_size(const aegis256x2_raf_ctx *ctx, uint64_t *size);

int aegis256x2_raf_sync(aegis256x2_raf_ctx *ctx);

void aegis256x2_raf_close(aegis256x2_raf_ctx *ctx);

int aegis256x2_raf_merkle_rebuild(aegis256x2_raf_ctx *ctx);

int aegis256x2_raf_merkle_verify(aegis256x2_raf_ctx *ctx, uint64_t *corrupted_chunk);

/* Opaque context for AEGIS-256X4 RAF operations. Master key is 32 bytes. */
typedef struct aegis256x4_raf_ctx {
    CRYPTO_ALIGN(64) uint8_t opaque[512];
} aegis256x4_raf_ctx;

int aegis256x4_raf_create(aegis256x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis256x4_raf_open(aegis256x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg, const uint8_t *master_key);

int aegis256x4_raf_read(aegis256x4_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                        uint64_t offset) __attribute__((warn_unused_result));

int aegis256x4_raf_write(aegis256x4_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                         size_t len, uint64_t offset) __attribute__((warn_unused_result));

int aegis256x4_raf_truncate(aegis256x4_raf_ctx *ctx, uint64_t size);

int aegis256x4_raf_get_size(const aegis256x4_raf_ctx *ctx, uint64_t *size);

int aegis256x4_raf_sync(aegis256x4_raf_ctx *ctx);

void aegis256x4_raf_close(aegis256x4_raf_ctx *ctx);

int aegis256x4_raf_merkle_rebuild(aegis256x4_raf_ctx *ctx);

int aegis256x4_raf_merkle_verify(aegis256x4_raf_ctx *ctx, uint64_t *corrupted_chunk);

#ifdef __cplusplus
}
#endif

#endif
