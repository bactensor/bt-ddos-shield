from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, Literal, TypeVar

import ecies
from ecies.config import Config

from bt_ddos_shield.certificate_manager import PrivateKey, PublicKey


class EncryptionManagerException(Exception):
    pass


class EncryptionError(EncryptionManagerException):
    pass


class DecryptionError(EncryptionManagerException):
    pass


PrivateKeyType = TypeVar('PrivateKeyType')
PublicKeyType = TypeVar('PublicKeyType')


class AbstractEncryptionManager(Generic[PrivateKeyType, PublicKeyType], ABC):
    """
    Abstract base class for manager handling manifest file encryption.
    """

    @abstractmethod
    def encrypt(self, public_key: PublicKeyType, data: bytes) -> bytes:
        """
        Encrypts given data using the provided public key. Throws EncryptionError if encryption fails.
        """
        pass

    @abstractmethod
    def decrypt(self, private_key: PrivateKeyType, data: bytes) -> bytes:
        """
        Decrypts given data using the provided private key. Throws DecryptionError if decryption fails.
        """
        pass


class ECIESEncryptionManager(AbstractEncryptionManager[PrivateKey, PublicKey]):
    """
    Encryption manager implementation using ECIES algorithm.

    Public and private keys are ed25519 keys in hex format.
    """

    _CURVE: Literal['ed25519'] = 'ed25519'
    _ECIES_CONFIG = Config(elliptic_curve=_CURVE)

    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        try:
            return ecies.encrypt(public_key, data, config=self._ECIES_CONFIG)
        except Exception as e:
            raise EncryptionError(f'Encryption failed: {e}') from e

    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        try:
            return ecies.decrypt(private_key, data, config=self._ECIES_CONFIG)
        except Exception as e:
            raise DecryptionError(f'Decryption failed: {e}') from e
