"""
Compatibility tests between the C library and middleware_legacy pwenc implementations.
"""

import base64
import os
import pytest
from Crypto.Cipher import AES
from Crypto.Util import Counter

import truenas_pypwenc

# Constants from middleware_legacy
PWENC_BLOCK_SIZE = 32
PWENC_PADDING = b'{'


@pytest.fixture
def shared_secret():
    """Create a known secret for testing both implementations."""
    # Create a deterministic 32-byte secret for testing
    secret = b'0123456789abcdef' * 2  # 32 bytes

    # Write to /data/pwenc_secret
    os.makedirs('/data', exist_ok=True)
    with open('/data/pwenc_secret', 'wb') as f:
        f.write(secret)

    yield secret

    # Cleanup
    if os.path.exists('/data/pwenc_secret'):
        os.unlink('/data/pwenc_secret')


def middleware_legacy_encrypt(data):
    """Middleware legacy encrypt function implementation."""
    data = data.encode('utf8')

    def pad(x):
        return x + (PWENC_BLOCK_SIZE - len(x) % PWENC_BLOCK_SIZE) * PWENC_PADDING

    nonce = os.urandom(8)

    # Get secret from file
    with open('/data/pwenc_secret', 'rb') as f:
        secret = f.read()

    cipher = AES.new(secret, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
    encoded = base64.b64encode(nonce + cipher.encrypt(pad(data)))
    return encoded.decode()


def middleware_legacy_decrypt(encrypted, _raise=False):
    """Middleware legacy decrypt function implementation."""
    if not encrypted:
        return ''

    try:
        encrypted = base64.b64decode(encrypted)
        nonce = encrypted[:8]
        encrypted = encrypted[8:]

        # Get secret from file
        with open('/data/pwenc_secret', 'rb') as f:
            secret = f.read()

        cipher = AES.new(secret, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
        return cipher.decrypt(encrypted).rstrip(PWENC_PADDING).decode('utf8')
    except Exception:
        if _raise:
            raise
        return ''


def test_c_encrypt_middleware_legacy_decrypt(shared_secret):
    """Test that middleware_legacy can decrypt data encrypted by C library."""
    ctx = truenas_pypwenc.get_context()

    test_data = "Hello, World!"

    # Encrypt with C library
    c_encrypted = ctx.encrypt(test_data.encode('utf-8'))

    # Decrypt with middleware_legacy
    middleware_legacy_decrypted = middleware_legacy_decrypt(c_encrypted.decode('utf-8'))
    assert middleware_legacy_decrypted == test_data


def test_middleware_legacy_encrypt_c_decrypt(shared_secret):
    """Test that C library can decrypt data encrypted by middleware_legacy."""
    ctx = truenas_pypwenc.get_context()

    test_data = "Hello, World!"

    # Encrypt with middleware_legacy
    middleware_legacy_encrypted = middleware_legacy_encrypt(test_data)

    # Decrypt with C library
    c_decrypted = ctx.decrypt(middleware_legacy_encrypted.encode('utf-8'))
    decrypted_str = c_decrypted.decode('utf-8').rstrip('{')
    assert decrypted_str == test_data
