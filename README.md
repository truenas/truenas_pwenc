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
- **Automatic secret reloading** via inotify file watching
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
- `PWENC_ERROR_PAYLOAD_TOO_LARGE` (-6) - Payload exceeds maximum size
- `PWENC_ERROR_WATCH_FAILED` (-7) - Failed to setup inotify watch
- `PWENC_ERROR_SECRET_RELOAD_FAILED` (-8) - Failed to reload secret file

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

## Usage

### Python API

```python
import truenas_pypwenc

# Create a context with automatic secret file creation
ctx = truenas_pypwenc.get_context(create=True)

# Encrypt data
plaintext = b"sensitive data"
encrypted = ctx.encrypt(plaintext)

# Decrypt data
decrypted = ctx.decrypt(encrypted)
assert decrypted == plaintext
```

### Automatic Secret Reloading

Enable inotify watching to automatically reload the secret when the file changes:

```python
import truenas_pypwenc

# Create context with watch enabled
ctx = truenas_pypwenc.get_context(watch=True, secret_path="/data/pwenc_secret")

# Check if watching is active
print(ctx.watching)  # True

# Encrypt/decrypt operations will automatically reload the secret
# if the file is modified, deleted, or replaced (atomic rename)
encrypted = ctx.encrypt(b"data")
decrypted = ctx.decrypt(encrypted)
```

The watch feature monitors the secret file for:
- **File modifications** (`IN_MODIFY`)
- **File deletion** (`IN_DELETE_SELF`)
- **File moves** (`IN_MOVE_SELF`)
- **Atomic replacements** (rename over the file path)

When any of these events occur, the next encrypt/decrypt operation will:
1. Check for inotify events (non-blocking)
2. Reload the secret from disk if changes detected
3. Proceed with the operation

### C API

```c
#include <truenas_pwenc.h>

pwenc_ctx_t *ctx;
pwenc_error_t error;
bool created;

// Initialize context with watch enabled
int ret = pwenc_init_context("/data/pwenc_secret",
                              PWENC_OPEN_CREATE | PWENC_OPEN_WATCH,
                              &ctx, &created, &error);

// Check if watching is active
if (pwenc_is_watching(ctx)) {
    // Automatic reload on file changes
}

// Encrypt/decrypt operations
pwenc_datum_t plaintext = {.data = "secret", .size = 6};
pwenc_datum_t ciphertext;
ret = pwenc_encrypt(ctx, &plaintext, &ciphertext, &error);

// Cleanup
pwenc_free_context(ctx);
```

## Configuration

The default secret file location is `/data/pwenc_secret`. This can be overridden when opening a context.

Environment variable `FREENAS_PWENC_SECRET` can also be used to specify the secret file path.

## License

Licensed under the GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later).