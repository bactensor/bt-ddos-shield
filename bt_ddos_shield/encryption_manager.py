from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, Literal, NamedTuple, TypeVar, TypeAlias

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


class EncryptionCertificate(NamedTuple):
    private_key: PrivateKey
    public_key: PublicKey


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

    CURVE: Literal['ed25519'] = 'ed25519'

    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        try:
            # Remove the algorithm identifier before passing to ecies.encrypt
            raw_public_key = public_key[2:]
            config = Config(elliptic_curve=self.CURVE)
            return ecies.encrypt(raw_public_key, data, config=config)
        except Exception as e:
            raise EncryptionError(f'Encryption failed: {e}') from e

    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        try:
            config = Config(elliptic_curve=self.CURVE)
            return ecies.decrypt(private_key, data, config=config)
        except Exception as e:
            raise DecryptionError(f'Decryption failed: {e}') from e

    @classmethod
    def generate_certificate(cls) -> EncryptionCertificate:
        ecies_private_key = EciesPrivateKey(cls.CURVE)
        private_key: str = ecies_private_key.to_hex()
        raw_public_key: bytes = ecies_private_key.public_key.to_bytes()
        # Prepend the ED25519 algorithm identifier
        public_key = bytes([CertificateAlgorithmEnum.ED25519]) + raw_public_key

        return EncryptionCertificate(private_key, public_key.hex())

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
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        private_bytes = private_key.private_bytes_raw()
        private_hex = private_bytes.hex()

        # Create EciesPrivateKey to get the public key
        ecies_private_key = EciesPrivateKey.from_hex(cls.CURVE, private_hex)
        raw_public_key: bytes = ecies_private_key.public_key.to_bytes()
        # Prepend the ED25519 algorithm identifier
        public_key = bytes([CertificateAlgorithmEnum.ED25519]) + raw_public_key

        return EncryptionCertificate(private_hex, public_key.hex())
