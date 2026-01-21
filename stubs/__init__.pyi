"""
TrueNAS pwenc library - Type stubs

This module provides AES-256-CTR encryption/decryption using secrets
stored in memfd_secret for enhanced security.
"""

from typing import Optional

__all__ = ['PwencContext', 'PwencError', 'get_context', 'DEFAULT_SECRET_PATH']

DEFAULT_SECRET_PATH: str

class PwencError(RuntimeError):
    """
    Python wrapper around pwenc library errors.

    Attributes
    ----------
    code : int
        pwenc error code
    message : str
        human-readable error description
    """
    code: int
    message: str

class PwencContext:
    """
    Context for pwenc encryption and decryption operations.

    This object provides access to AES-256-CTR encryption/decryption
    using secrets stored in memfd_secret for enhanced security.
    Use truenas_pypwenc.get_context() to create instances.
    """

    @property
    def created(self) -> bool:
        """True if the secret file was created, False if it already existed"""
        ...

    @property
    def path(self) -> Optional[str]:
        """Path to the secret file used by this context"""
        ...

    @property
    def watching(self) -> bool:
        """True if inotify watching is active on the secret file"""
        ...

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-CTR and encode as base64.

        Parameters
        ----------
        data : bytes
            Input data to encrypt.

        Returns
        -------
        bytes
            Base64-encoded encrypted data with embedded nonce.

        Raises
        ------
        PwencError
            If encryption fails
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt base64-encoded data using AES-256-CTR.

        Parameters
        ----------
        data : bytes
            Base64-encoded encrypted data with embedded nonce.

        Returns
        -------
        bytes
            Decrypted plaintext data.

        Raises
        ------
        PwencError
            If decryption fails
        """
        ...

def get_context(
    *,
    create: bool = False,
    watch: bool = False,
    secret_path: Optional[str] = None
) -> PwencContext:
    """
    Create a new PwencContext instance for encryption and decryption operations.

    Parameters
    ----------
    create : bool, optional
        Whether to create a new secret file if one doesn't exist.
        Default is False.
    watch : bool, optional
        Whether to enable inotify watching on the secret file for automatic
        reload on changes. When enabled, encrypt/decrypt will check for file
        changes and reload the secret transparently.
        Default is False.
    secret_path : str, optional
        Path to secret file. If None, uses FREENAS_PWENC_SECRET environment
        variable or falls back to /data/pwenc_secret.

    Returns
    -------
    PwencContext
        An opened context ready for encryption/decryption operations.

    Raises
    ------
    PwencError
        If the context cannot be initialized
    """
    ...
