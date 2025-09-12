import os
import tempfile
import pytest
import truenas_pypwenc


def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt functionality."""
    ctx = truenas_pypwenc.get_context(create=True)

    test_data = b"Hello, World! This is a test string."

    encrypted = ctx.encrypt(test_data)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) > 0
    assert encrypted != test_data

    decrypted = ctx.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
    assert decrypted == test_data


@pytest.mark.parametrize("test_data", [
    b"short",
    b"A longer test string with various characters: !@#$%^&*()",
    b"x" * 1000,  # Long string
    b"unicode test: \xc3\xa9\xc3\xa1\xc3\xad\xc3\xb3\xc3\xba"
])
def test_encrypt_decrypt_various_data(test_data):
    """Test encrypt/decrypt operations with various data types."""
    ctx = truenas_pypwenc.get_context(create=True)

    encrypted = ctx.encrypt(test_data)
    decrypted = ctx.decrypt(encrypted)
    assert decrypted == test_data


def test_empty_data_raises_exception():
    """Test that empty data raises an exception."""
    ctx = truenas_pypwenc.get_context(create=True)

    with pytest.raises(Exception):
        ctx.encrypt(b"")


def test_context_attributes():
    """Test context attributes like created and path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = os.path.join(tmpdir, "test_secret")

        # Set environment variable to control secret path
        original_env = os.environ.get("FREENAS_PWENC_SECRET")
        os.environ["FREENAS_PWENC_SECRET"] = secret_path

        try:
            # First context should create the file
            ctx1 = truenas_pypwenc.get_context(create=True)
            assert ctx1.created is True
            assert ctx1.path == secret_path

            # Second context should use existing file
            ctx2 = truenas_pypwenc.get_context(create=True)
            assert ctx2.created is False
            assert ctx2.path == secret_path

        finally:
            # Restore original environment
            if original_env is not None:
                os.environ["FREENAS_PWENC_SECRET"] = original_env
            else:
                os.environ.pop("FREENAS_PWENC_SECRET", None)


def test_context_repr():
    """Test context __repr__ method."""
    ctx = truenas_pypwenc.get_context(create=True)
    repr_str = repr(ctx)
    assert "PwencContext(path=" in repr_str
    assert ctx.path in repr_str


def test_different_contexts_same_data():
    """Test that different contexts with same secret can decrypt each other's data."""
    test_data = b"Test data for cross-context compatibility"

    ctx1 = truenas_pypwenc.get_context(create=True)
    encrypted = ctx1.encrypt(test_data)

    ctx2 = truenas_pypwenc.get_context(create=False)
    decrypted = ctx2.decrypt(encrypted)

    assert decrypted == test_data


def test_invalid_decrypt_data():
    """Test decryption with invalid data."""
    ctx = truenas_pypwenc.get_context(create=True)

    # Test with invalid base64
    with pytest.raises(Exception):
        ctx.decrypt(b"not valid base64!")

    # Test with too short data
    with pytest.raises(Exception):
        ctx.decrypt(b"dGVzdA==")  # "test" in base64, too short


def test_encryption_produces_different_outputs():
    """Test that encrypting same data twice produces different outputs (due to random nonce)."""
    ctx = truenas_pypwenc.get_context(create=True)

    test_data = b"Same data encrypted twice"

    encrypted1 = ctx.encrypt(test_data)
    encrypted2 = ctx.encrypt(test_data)

    # Should be different due to random nonce
    assert encrypted1 != encrypted2

    # But both should decrypt to same original data
    assert ctx.decrypt(encrypted1) == test_data
    assert ctx.decrypt(encrypted2) == test_data


def test_large_data_encryption():
    """Test encryption/decryption of larger data."""
    ctx = truenas_pypwenc.get_context(create=True)

    # Create 10KB of test data
    test_data = b"0123456789" * 1024

    encrypted = ctx.encrypt(test_data)
    decrypted = ctx.decrypt(encrypted)

    assert decrypted == test_data
    assert len(decrypted) == 10240
