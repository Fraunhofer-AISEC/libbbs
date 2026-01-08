# libbbs

Specification-compliant and performant C implementation of the [BBS signature scheme](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) with little to no third party dependencies.

Provides a library `libbbs` implementing the `BLS12-381-SHA-256` and `BLS12-381-SHAKE-256` cipher suite.

The API is documented in `include/bbs.h` and the manual. See **bbs**(7).

## Build / Install from source

Dependencies:

- `cmake` (build only)
- blst (will be downloaded during build)
- libc providing the `getentropy` function.

```sh
$ mkdir build && cd build
$ cmake ..
$ make
$ make test         (recommended)
$ sudo make install
```

## Benchmark

Within `build`:

```sh
make bench
```

Benchmark (`bbs_bench_individual`) on Lenovo ThinkPad T14s Gen1 using clang:

- 2 messages each of size 64 bytes
- Disclosing first message only
- Runtime averaged over 1000 iterations without warmup

| Function                 | SHA256 (ms) | SHAKE256 (ms) |
| ------------------------ | ----------- | ------------- |
| key generation (SK & PK) | 0.174       | 0.172         |
| sign                     | 0.522       | 0.514         |
| verify                   | 1.299       | 1.288         |
| proof generation         | 1.190       | 1.178         |
| proof verification       | 1.643       | 1.631         |

