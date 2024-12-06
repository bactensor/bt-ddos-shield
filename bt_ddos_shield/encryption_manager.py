from abc import ABC, abstractmethod
import ecies

from bt_ddos_shield.utils import PublicKey, PrivateKey


class EncryptionManagerException(Exception):
    pass


class EncryptionError(EncryptionManagerException):
    pass


class DecryptionError(EncryptionManagerException):
    pass


class AbstractEncryptionManager(ABC):
    """
    Abstract base class for manager handling manifest file encryption.
    """

    @abstractmethod
    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        """
        Encrypts given data using the provided public key.
        """
        pass

    @abstractmethod
    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        """
        Decrypts given data using the provided private key.
        """
        pass


class ECIESEncryptionManager(AbstractEncryptionManager):
    """
    Encryption manager implementation using ECIES algorithm. Public and private keys are Ethereum (secp256k1) keys
    in hex format.
    """

    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        try:
            return ecies.encrypt(public_key, data)
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        try:
            return ecies.decrypt(private_key, data)
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
