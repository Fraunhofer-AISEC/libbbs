# libbbs

Specification-compliant and performant implementation of the [bbs signature scheme](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html).

Provides a library `libbbs` implementing the `BLS12381-SHA-256` and `BLS12-381-SHAKE-256` cipher suite.

## Setup

### Prerequisites

Dependencies:

- `gmp`
- `cmake` (build only)
- `` (`BLS12-381-SHAKE-256` only)

### Installation

```zsh
mkdir build
cd build
cmake ..
make install
```

`BBS_CIPHER_SUITE` cmake Options: `BLS12381-SHA-256` (default), `BLS12-381-SHAKE-256`.

### Test

```zsh
mkdir build
cd build
cmake ..
make -j
make test
```
