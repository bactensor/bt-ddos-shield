from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, NamedTuple, TypeVar

import ecies
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from ecies.keys import PrivateKey as EciesPrivateKey


if TYPE_CHECKING:
    from bt_ddos_shield.utils import PrivateKey, PublicKey


class EncryptionManagerException(Exception):
    pass


class EncryptionError(EncryptionManagerException):
    pass


class DecryptionError(EncryptionManagerException):
    pass


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
    def serialize_certificate(cls, certificate: CertType) -> EncryptionCertificate:
        """
        Serialize certificate public and private key.
        """
        pass

    @classmethod
    @abstractmethod
    def save_certificate(cls, certificate: CertType, path: str):
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


class CertificateAlgorithmEnum(enum.IntEnum):
    """Values are taken from coincurve.keys.PublicKey.__init__ method."""

    ECDSA_SECP256K1_UNCOMPRESSED = 4
    """ ECDSA using secp256k1 curve (uncompressed version) """


class ECIESEncryptionManager(AbstractEncryptionManager[EciesPrivateKey]):
    """
    Encryption manager implementation using ECIES algorithm. Public and private keys are Coincurve (secp256k1) keys
    in hex format.
    """

    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        try:
            return ecies.encrypt(public_key, data)
        except Exception as e:
            raise EncryptionError(f'Encryption failed: {e}') from e

    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        try:
            return ecies.decrypt(private_key, data)
        except Exception as e:
            raise DecryptionError(f'Decryption failed: {e}') from e

    @classmethod
    def generate_certificate(cls) -> EciesPrivateKey:
        return EciesPrivateKey('secp256k1')

    @classmethod
    def serialize_certificate(cls, certificate: EciesPrivateKey) -> EncryptionCertificate:
        private_key: str = certificate.to_hex()
        public_key: bytes = certificate.public_key.to_bytes(compressed=False)
        assert public_key[0] == CertificateAlgorithmEnum.ECDSA_SECP256K1_UNCOMPRESSED
        return EncryptionCertificate(private_key, public_key.hex())

    @classmethod
    def save_certificate(cls, certificate: EciesPrivateKey, path: str):
        # Convert hex private key to cryptography private key
        private_key_bytes = bytes.fromhex(certificate.to_hex())
        private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, byteorder='big'), ec.SECP256K1())

        # Serialize to PEM format
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(path, 'wb') as f:
            f.write(pem_data)

    @classmethod
    def load_certificate(cls, path: str) -> EciesPrivateKey:
        # Load PEM private key
        with open(path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Convert to hex format for EciesPrivateKey
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError('The loaded key is not an elliptic curve private key')

        private_numbers = private_key.private_numbers()
        private_value = private_numbers.private_value
        private_bytes = private_value.to_bytes(32, byteorder='big')
        private_hex = private_bytes.hex()

        return EciesPrivateKey.from_hex('secp256k1', private_hex)
