from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, Literal, TypeAlias, TypeVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from ecies.keys import PrivateKey as EciesPrivateKey

CertificateType = TypeVar('CertificateType')


class AbstractCertificateManager(Generic[CertificateType], ABC):
    """
    Abstract base class for certificate management.
    """

    @classmethod
    @abstractmethod
    def generate_certificate(cls) -> CertificateType:
        """
        Generates certificate object.
        """
        pass

    @classmethod
    @abstractmethod
    def save_certificate(cls, certificate: CertificateType, path: str) -> None:
        """
        Save certificate to disk.
        """
        pass

    @classmethod
    @abstractmethod
    def load_certificate(cls, path: str) -> CertificateType:
        """
        Load certificate from disk.
        """
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
class Certificate:
    algorithm: CertificateAlgorithmEnum
    public_key: PublicKey
    private_key: PrivateKey


class EDDSACertificateManager(AbstractCertificateManager[Certificate]):
    """
    Certificate manager implementation using EDDSA algorithm.

    Public and private keys are ed25519 keys in hex format.
    """

    _CURVE: Literal['ed25519'] = 'ed25519'

    @classmethod
    def generate_certificate(cls) -> Certificate:
        ecies_private_key = EciesPrivateKey(cls._CURVE)

        return Certificate(
            private_key=ecies_private_key.to_hex(),
            public_key=ecies_private_key.public_key.to_hex(),
            algorithm=CertificateAlgorithmEnum.ED25519,
        )

    @classmethod
    def save_certificate(cls, certificate: Certificate, path: str) -> None:
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
    def load_certificate(cls, path: str) -> Certificate:
        with open(path, 'rb') as f:
            private_key = f.read()

        private_key_bytes = serialization.load_pem_private_key(private_key, password=None).private_bytes_raw()
        ecies_private_key = EciesPrivateKey.from_hex(cls._CURVE, private_key_bytes.hex())

        return Certificate(
            private_key=ecies_private_key.to_hex(),
            public_key=ecies_private_key.public_key.to_hex(),
            algorithm=CertificateAlgorithmEnum.ED25519,
        )
