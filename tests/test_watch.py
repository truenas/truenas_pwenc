import os
import tempfile
import shutil
import pytest
import truenas_pypwenc


@pytest.fixture
def temp_secret_dir():
    """Create a temporary directory for test secrets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def secret_path(temp_secret_dir):
    """Create a secret path in the temporary directory."""
    return os.path.join(temp_secret_dir, "test_secret")


def test_watch_enabled():
    """Test that watch flag enables watching."""
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = os.path.join(tmpdir, "test_secret")

        # Create context without watch
        ctx_no_watch = truenas_pypwenc.get_context(create=True, watch=False, secret_path=secret_path)
        assert ctx_no_watch.watching is False

        # Create context with watch
        ctx_with_watch = truenas_pypwenc.get_context(create=False, watch=True, secret_path=secret_path)
        assert ctx_with_watch.watching is True


def test_watch_file_renamed_over(secret_path):
    """Test that encrypting/decrypting works when secret file is atomically replaced (renamed over)."""
    # Create initial secret and context with watch
    ctx = truenas_pypwenc.get_context(create=True, watch=True, secret_path=secret_path)
    assert ctx.watching is True

    # Encrypt some data with original secret
    test_data = b"Test data before secret change"
    encrypted1 = ctx.encrypt(test_data)

    # Verify we can decrypt with original secret
    decrypted1 = ctx.decrypt(encrypted1)
    assert decrypted1 == test_data

    # Generate a new secret file and atomically replace the old one
    temp_secret = secret_path + ".new"
    # Create a new context to generate a new secret
    ctx_new = truenas_pypwenc.get_context(create=True, watch=False, secret_path=temp_secret)

    # Encrypt data with new secret to verify it's different
    encrypted_new = ctx_new.encrypt(test_data)

    # Atomically replace old secret with new secret (rename over)
    os.rename(temp_secret, secret_path)

    # Now encrypt with the original context - should use new secret after reload
    encrypted2 = ctx.encrypt(test_data)

    # encrypted2 should be decryptable by ctx_new (which has the new secret)
    decrypted_by_new = ctx_new.decrypt(encrypted2)
    assert decrypted_by_new == test_data

    # encrypted1 (from old secret) should NOT be decryptable anymore
    # This will fail because the secret changed
    with pytest.raises(Exception):
        ctx.decrypt(encrypted1)


def test_watch_file_renamed(secret_path):
    """Test that encrypting/decrypting fails when secret file is moved away."""
    # Create initial secret and context with watch
    ctx = truenas_pypwenc.get_context(create=True, watch=True, secret_path=secret_path)
    assert ctx.watching is True

    # Encrypt some data with original secret
    test_data = b"Test data before secret move"
    encrypted = ctx.encrypt(test_data)
    decrypted = ctx.decrypt(encrypted)
    assert decrypted == test_data

    # Move the secret file away (not replaced)
    moved_path = secret_path + ".moved"
    os.rename(secret_path, moved_path)

    # Try to encrypt - should fail because secret file is gone
    with pytest.raises(Exception) as exc_info:
        ctx.encrypt(test_data)

    # Verify error is about missing file or reload failure
    error_msg = str(exc_info.value).lower()
    assert "not found" in error_msg or "reload" in error_msg or "open" in error_msg


def test_watch_file_deleted(secret_path):
    """Test that encrypting/decrypting fails when secret file is deleted."""
    # Create initial secret and context with watch
    ctx = truenas_pypwenc.get_context(create=True, watch=True, secret_path=secret_path)
    assert ctx.watching is True

    # Encrypt some data with original secret
    test_data = b"Test data before secret deletion"
    encrypted = ctx.encrypt(test_data)
    decrypted = ctx.decrypt(encrypted)
    assert decrypted == test_data

    # Delete the secret file
    os.unlink(secret_path)

    # Try to decrypt - should fail because secret file is gone
    with pytest.raises(Exception) as exc_info:
        ctx.decrypt(encrypted)

    # Verify error is about missing file or reload failure
    error_msg = str(exc_info.value).lower()
    assert "not found" in error_msg or "reload" in error_msg or "open" in error_msg


def test_watch_file_modified(secret_path):
    """Test that secret is reloaded when file is modified in-place."""
    # Create initial secret and context with watch
    ctx = truenas_pypwenc.get_context(create=True, watch=True, secret_path=secret_path)
    assert ctx.watching is True

    # Encrypt some data with original secret
    test_data = b"Test data before secret modification"
    encrypted1 = ctx.encrypt(test_data)
    decrypted1 = ctx.decrypt(encrypted1)
    assert decrypted1 == test_data

    # Generate a new secret at a different location
    temp_secret = secret_path + ".new"
    ctx_new = truenas_pypwenc.get_context(create=True, watch=False, secret_path=temp_secret)

    # Copy the new secret over the old one (this triggers IN_MODIFY)
    shutil.copy2(temp_secret, secret_path)

    # Now encrypt with the original context - should use new secret after reload
    encrypted2 = ctx.encrypt(test_data)

    # encrypted2 should be decryptable by ctx_new (which has the new secret)
    decrypted_by_new = ctx_new.decrypt(encrypted2)
    assert decrypted_by_new == test_data

    # Old encrypted data should no longer decrypt
    with pytest.raises(Exception):
        ctx.decrypt(encrypted1)


def test_watch_no_reload_when_file_unchanged(secret_path):
    """Test that operations work normally when file hasn't changed."""
    # Create initial secret and context with watch
    ctx = truenas_pypwenc.get_context(create=True, watch=True, secret_path=secret_path)
    assert ctx.watching is True

    # Encrypt and decrypt multiple times without changing the file
    test_data = b"Test data with no file changes"

    for i in range(5):
        encrypted = ctx.encrypt(test_data)
        decrypted = ctx.decrypt(encrypted)
        assert decrypted == test_data


def test_watch_decrypt_after_reload(secret_path):
    """Test that decrypt works with new secret after reload."""
    # Create initial secret and context with watch
    ctx = truenas_pypwenc.get_context(create=True, watch=True, secret_path=secret_path)
    assert ctx.watching is True

    # Replace secret with a new one
    temp_secret = secret_path + ".new"
    ctx_new = truenas_pypwenc.get_context(create=True, watch=False, secret_path=temp_secret)

    # Encrypt with the new secret
    test_data = b"Test data with new secret"
    encrypted_new = ctx_new.encrypt(test_data)

    # Replace old secret with new one
    os.rename(temp_secret, secret_path)

    # Original context should now be able to decrypt data encrypted with new secret
    decrypted = ctx.decrypt(encrypted_new)
    assert decrypted == test_data
