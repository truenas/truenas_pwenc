# TrueNAS pwenc

A data encryption library for TrueNAS, providing secure encryption and decryption of arbitrary data using AES-256-CTR encryption with base64 encoding.

## Overview

The TrueNAS pwenc library consists of:
- A C library (`libtruenas_pwenc`) providing core encryption/decryption functionality
- A Python extension module (`truenas_pypwenc`) offering Python bindings

## Features

- **AES-256-CTR encryption** with random 8-byte nonces
- **Base64 encoding** for safe text storage
- **Secure memory handling** using memfd_secret
- **Python bindings** for easy integration

## Architecture

The library uses a context-based approach where operations are performed through a `pwenc_ctx_t` structure. The encryption secret is stored securely using Linux's memfd_secret functionality and can be automatically generated if needed.

### Error Codes

- `PWENC_SUCCESS` (0) - Operation completed successfully
- `PWENC_ERROR_INVALID_INPUT` (-1) - Invalid input parameters
- `PWENC_ERROR_MEMORY` (-2) - Memory allocation failure
- `PWENC_ERROR_CRYPTO` (-3) - Cryptographic operation failure
- `PWENC_ERROR_IO` (-4) - I/O operation failure
- `PWENC_ERROR_SECRET_NOT_FOUND` (-5) - Secret file not found

## Building

### C Library

```bash
make library
```

### Python Extension

```bash
pip install .
```

### Debian Packages

The project includes Debian packaging files for creating distribution packages.

## Dependencies

- OpenSSL (libssl, libcrypto)
- libbsd
- Python 3.10+ (for Python bindings)

## Installation

### From Source

```bash
make install
```

### Python Package

```bash
pip install .
```

## Configuration

The default secret file location is `/data/pwenc_secret`. This can be overridden when opening a context.

## License

Licensed under the GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later).