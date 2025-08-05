from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, Literal, TypeVar, TypeAlias

import ecies
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from ecies.keys import PrivateKey as EciesPrivateKey
from ecies.config import Config


class EncryptionManagerException(Exception):
    pass


class EncryptionError(EncryptionManagerException):
    pass


class DecryptionError(EncryptionManagerException):
    pass


# Type aliases for encryption keys
PrivateKey: TypeAlias = str
PublicKey: TypeAlias = str


class CertificateAlgorithmEnum(enum.IntEnum):
    """
    Certificate algorithm.

    Currently only EdDSA using ed25519 curve is supported.
    """

    ED25519 = 1
    """ EdDSA using ed25519 curve """


@dataclass(frozen=True)
class EncryptionCertificate:
    algorithm: CertificateAlgorithmEnum
    public_key: PublicKey
    private_key: PrivateKey


CertType = TypeVar('CertType')


class AbstractEncryptionManager(Generic[CertType], ABC):
    """
    Abstract base class for manager handling manifest file encryption.
    """

    @abstractmethod
    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        """
        Encrypts given data using the provided public key. Throws EncryptionError if encryption fails.
        """
        pass

    @abstractmethod
    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        """
        Decrypts given data using the provided private key. Throws DecryptionError if decryption fails.
        """
        pass

    @classmethod
    @abstractmethod
    def generate_certificate(cls) -> CertType:
        """
        Generates certificate object, which will be used for encryption of manifest data.
        """
        pass

    @classmethod
    @abstractmethod
    def save_certificate(cls, certificate: CertType, path: str) -> None:
        """
        Save certificate to disk.
        """
        pass

    @classmethod
    @abstractmethod
    def load_certificate(cls, path: str) -> CertType:
        """
        Load certificate from disk.
        """
        pass


class ECIESEncryptionManager(AbstractEncryptionManager[EncryptionCertificate]):
    """
    Encryption manager implementation using ECIES algorithm. Public and private keys are ed25519 keys
    in hex format.
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

    @classmethod
    def generate_certificate(cls) -> EncryptionCertificate:
        ecies_private_key = EciesPrivateKey(cls._CURVE)

        return EncryptionCertificate(
            private_key=ecies_private_key.to_hex(),
            public_key=ecies_private_key.public_key.to_hex(),
            algorithm=CertificateAlgorithmEnum.ED25519,
        )

    @classmethod
    def save_certificate(cls, certificate: EncryptionCertificate, path: str) -> None:
        # Convert hex private key to cryptography private key
        private_key_bytes = bytes.fromhex(certificate.private_key)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

        # Serialize to PEM format
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(path, 'wb') as f:
            f.write(pem_data)

    @classmethod
    def load_certificate(cls, path: str) -> EncryptionCertificate:
        with open(path, 'rb') as f:
            private_key = f.read()

        private_key_bytes = serialization.load_pem_private_key(private_key, password=None).private_bytes_raw()
        ecies_private_key = EciesPrivateKey.from_hex(cls._CURVE, private_key_bytes.hex())

        return EncryptionCertificate(
            private_key=ecies_private_key.to_hex(),
            public_key=ecies_private_key.public_key.to_hex(),
            algorithm=CertificateAlgorithmEnum.ED25519,
        )
