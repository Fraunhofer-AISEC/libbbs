# libbbs

Specification-compliant and performant implementation of the [bbs signature scheme](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html).

Provides a library `libbbs` implementing the `BLS12381-SHA-256` and `BLS12-381-SHAKE-256` cipher suite.

## Setup

### Prerequisites

Dependencies:

- `gmp`
- `cmake` (build only)

```zsh
mkdir build
cd build
cmake ..
```

### Installation

Within `build`:

```zsh
make install
```

### Test

Within `build`:

```zsh
make
make test
```

### Benchmark

Within `build`:

```zsh
make bench
```
