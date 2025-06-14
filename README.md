# libbbs

Specification-compliant and performant C implementation of the [BBS signature scheme](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) with little to no third party dependencies.

Provides a library `libbbs` implementing the `BLS12-381-SHA-256` and `BLS12-381-SHAKE-256` cipher suite.

## Prerequisites

Dependencies:

- `cmake` (build only)
- `gmp` (optional, faster than the default)

```zsh
mkdir build
cd build
cmake .. # Without GMP or
cmake -DRELIC_ARITH="gmp" .. # (if you have gmp)
```

## Installation

Within `build`:

```zsh
make install
```

## Test

Within `build`:

```zsh
make
make test
```

## Benchmark

Within `build`:

```zsh
./test/bbs-test-bench
```

 

Benchmark (`bbs_bench_individual`) on M1 Pro 2021 16GB with `-DRELIC_ARITH="gmp"`:

- 2 messages each of size 64 bytes
- Disclosing first message only
- Runtime averaged over 1000 iterations without warmup

| Function                 | SHA256 (ms) | SHAKE256 (ms) |
| ------------------------ | ----------- | ------------- |
| key generation (SK & PK) | 0,174       | 0,172         |
| sign                     | 1,995       | 1,888         |
| verify                   | 3,877       | 3,829         |
| proof generation         | 3,289       | 3,220         |
| proof verification       | 4,532       | 4,482         |


## Documentation

See https://fraunhofer-aisec.github.io/libbbs/doxy/html/

## Code coverage

See https://fraunhofer-aisec.github.io/libbbs/lcov
