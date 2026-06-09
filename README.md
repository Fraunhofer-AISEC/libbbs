# libbbs

Specification-compliant and performant C implementation of the [BBS signature scheme](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) and its extensions, with little to no third party dependencies.[^1]

Provides a library `libbbs` implementing three layers of functionality:

- **BBS signatures** ([draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)) — multi-message signatures with selective disclosure proofs. Cipher suites: `BLS12-381-SHA-256` and `BLS12-381-SHAKE-256`.
- **Blind BBS signatures** ([draft-irtf-cfrg-bbs-blind-signatures-02](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html)) — extends BBS to allow messages unknown to the signer to be included in the signature via a commitment. Cipher suites: `BLS12-381-BLIND-SHA-256` and `BLS12-381-BLIND-SHAKE-256`.
- **BBS with per-verifier pseudonyms** ([draft-irtf-cfrg-bbs-per-verifier-linkability-02](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-per-verifier-linkability-02.html)) — extends blind BBS to bind prover-controlled secrets into the signature, enabling stable per-verifier pseudonyms without revealing the prover's identity across contexts. Cipher suites: `BLS12-381-BLIND-NYM-SHA-256` and `BLS12-381-BLIND-NYM-SHAKE-256`.

The API is documented in `include/bbs.h`, `include/bbs_blind.h`, `include/bbs_blind_with_nym.h`, and the manual. See
[**bbs**(7)](https://fraunhofer-aisec.github.io/libbbs/).

[^1]: The calling application needs to provide a source of randomness via
    [**getentropy**(3)](https://pubs.opengroup.org/onlinepubs/9799919799/). On modern POSIX platforms, this function is included in libc.

## Build / Install from source

Build dependencies:

- `cmake`
- [blst](https://github.com/supranational/blst) (automatically downloaded / statically linked)

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

