from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, NamedTuple, TypeVar

import ecies
from coincurve.keys import PrivateKey as CoincurvePrivateKey

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


class ECIESEncryptionManager(AbstractEncryptionManager[CoincurvePrivateKey]):
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
    def generate_certificate(cls) -> CoincurvePrivateKey:
        return ecies.utils.generate_key()

    @classmethod
    def serialize_certificate(cls, certificate: CoincurvePrivateKey) -> EncryptionCertificate:
        private_key: str = certificate.to_hex()
        public_key: bytes = certificate.public_key.format(compressed=False)
        assert public_key[0] == CertificateAlgorithmEnum.ECDSA_SECP256K1_UNCOMPRESSED
        return EncryptionCertificate(private_key, public_key.hex())

    @classmethod
    def save_certificate(cls, certificate: CoincurvePrivateKey, path: str):
        with open(path, 'wb') as f:
            f.write(certificate.to_pem())

    @classmethod
    def load_certificate(cls, path: str) -> CoincurvePrivateKey:
        with open(path, 'rb') as f:
            return CoincurvePrivateKey.from_pem(f.read())
