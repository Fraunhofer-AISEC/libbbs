# libbbs

Specification-compliant and performant implementation of the [bbs signature scheme](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html).

Provides a library `libbbs` implementing the `BLS12381-SHA-256` cipher suite.

## Setup

### Prerequisites

Dependencies:

- `gmp`
- `cmake` (build only)

### Installation

```zsh
mkdir build
cd build
cmake ..
make install
```

### Test

```zsh
mkdir build
cd build
cmake ..
make -j
make test
```

