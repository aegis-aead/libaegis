# libaegis

Portable C implementations of the [AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) family of high-performance authenticated ciphers (AEGIS-128L, AEGIS-128X2, AEGIS-128X4, AEGIS-256, AEGIS-256X2, AEGIS-256X4), with runtime CPU detection.

## Features

- AEGIS-128L with 16 and 32 bytes tags (software, AES-NI, ARM Crypto, Altivec)
- AEGIS-128X2 with 16 and 32 bytes tags (software, VAES + AVX2, AES-NI, ARM Crypto, Altivec)
- AEGIS-128X4 with 16 and 32 bytes tags (software, AVX512, VAES + AVX2, AES-NI, ARM Crypto, Altivec)
- AEGIS-256 with 16 and 32 bytes tags (software, AES-NI, ARM Crypto, Altivec)
- AEGIS-256X2 with 16 and 32 bytes tags (software, VAES + AVX2, AES-NI, ARM Crypto, Altivec)
- AEGIS-256X4 with 16 and 32 bytes tags (software, AVX512, VAES + AVX2, AES-NI, ARM Crypto, Altivec)
- All variants of AEGIS-MAC, supporting incremental updates.
- Encryption and decryption with attached and detached tags
- Incremental encryption and decryption.
- Unauthenticated encryption and decryption (not recommended - only implemented for specific protocols)
- Deterministic pseudorandom stream generation.

## Installation

Note that the compiler makes a difference. Zig (or a recent `clang` with target-specific options such as `-march=native`) produces more efficient code than `gcc`.

### Compilation with `zig`:

```sh
zig build -Drelease
```

To build the library as a shared object using the `-Dlink-mode` option:
```sh
zig build -Dlink-mode=dynamic -Drelease
```

The library and headers are installed in the `zig-out` folder.

To favor performance over side-channel mitigations on devices without hardware acceleration, add `-Dfavor-performance`:

```sh
zig build -Drelease -Dfavor-performance
```

A benchmark can also be built with the `-Dwith-benchmark` option:

```sh
zig build -Drelease -Dfavor-performance -Dwith-benchmark
```


`libaegis` doesn't need WASI nor any extension to work on WebAssembly. The `wasm32-freestanding` target is fully supported.

WebAssembly extensions such as `bulk_memory` and `simd128` can be enabled by adding `-Dcpu=baseline+bulk_memory+simd128` to the command line.

### Compilation with `cmake`:

```sh
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/install/prefix ..
make install
```
To build the library as a shared library, add `-DBUILD_SHARED_LIBS=On`.

To favor performance over side-channel mitigations on devices without hardware acceleration, add `-DFAVOR_PERFORMANCE`.

### Direct inclusion

Copy everything in `src` directly into your project, and compile everything like regular C code. No special configuration is required.

## Usage

Include `<aegis.h>` and call `aegis_init()` prior to doing anything else with the library.

`aegis_init()` checks the CPU capabilities in order to later use the fastest implementations.

## Bindings

- [`aegis`](https://crates.io/crates/aegis) is a set of bindings for Rust.
- [`go-libaegis`](https://github.com/aegis-aead/go-libaegis) is a set of bindings for Go.

## Libaegis TLS users

- [`fizz`](https://github.com/facebookincubator/fizz) is Facebook's implementation of TLS 1.3.
- [`picotls`](https://github.com/h2o/picotls) is a TLS 1.3 implementation in C, with support for the AEGIS cipher suites.
- [`h2o`](https://h2o.examp1e.net) is an HTTP/{1,2,3} server with support for the AEGIS cipher suites.

## Other implementations

[Other AEGIS implementations](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead?tab=readme-ov-file#known-implementations) are also available for most programming languages.

Recommended for applications specifically targeting environments without AES instructions: [aegis-bitsliced](https://github.com/aegis-aead/aegis-bitsliced).

Recommended for applications targeting a specific x86_64 CPU: [aegis-jasmin](https://github.com/aegis-aead/aegis-jasmin).

The [aegis-aead GitHub organization](https://github.com/orgs/aegis-aead/repositories) also hosts AEGIS patches for [OpenSSL](https://github.com/aegis-aead/openssl) and [BoringSSL](https://github.com/aegis-aead/boringssl).

## Key differences between AEGIS variants

| **Feature**        | **AEGIS-128L**                                          | **AEGIS-256**                                           | **AEGIS-128X2**                                                           | **AEGIS-128X4**                                     | **AEGIS-256X2**                                                          | **AEGIS-256X4**                                    |
| ------------------ | ------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------- |
| **Key Length**     | 128 bits                                                | 256 bits                                                | 128 bits                                                                  | 128 bits                                            | 256 bits                                                                 | 256 bits                                           |
| **Nonce Length**   | 128 bits                                                | 256 bits                                                | 128 bits                                                                  | 128 bits                                            | 256 bits                                                                 | 256 bits                                           |
| **State Size**     | 1024 bits (8 x 128-bit blocks)                          | 768 bits (6 x 128-bit blocks)                           | 2048 bits (2 x 1024-bit states)                                           | 4096 bits (4 x 1024-bit states)                     | 1536 bits (2 x 768-bit states)                                           | 3072 bits (4 x 768-bit states)                     |
| **Input Rate**     | 256 bits per update                                     | 128 bits per update                                     | 512 bits per update                                                       | 1024 bits per update                                | 256 bits per update                                                      | 512 bits per update                                |
| **Performance**    | High on standard CPUs, optimized for small memory usage | High on standard CPUs, optimized for small memory usage | Generally faster than AEGIS-128L even without AVX2, even faster with AVX2 | Generally faster than AEGIS-128L, best with AVX-512 | Generally faster than AEGIS-256 even without AVX2, even faster with AVX2 | Generally faster than AEGIS-256, best with AVX-512 |
| **Security Level** | 128-bit security                                        | 256-bit security                                        | 128-bit security                                                          | 128-bit security                                    | 256-bit security                                                         | 256-bit security                                   |

## Benchmark results

AEGIS is very fast on CPUs with parallel execution pipelines and AES support.

The following results are derived from libaegis, which has been optimized primarily for portability and readability. Other implementations, such as `jasmin-aegis` or the Zig implementations, may demonstrate better performance.

### Encryption (16 KB)

![AEGIS benchmark results](img/bench-encryption.png)

### Authentication (64 KB)

![AEGIS-MAC benchmark results](img/bench-mac.png)

### Mobile benchmarks

![AEGIS mobile benchmark results](img/bench-mobile.png)
