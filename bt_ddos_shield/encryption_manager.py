import hashlib
import struct
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding

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


class AesRsaEncryptionManager(AbstractEncryptionManager):
    """
    Encryption manager implementation using AES and RSA algorithms. Public and private keys are RSA keys in PEM format.
    """

    def encrypt(self, public_key: PublicKey, data: bytes) -> bytes:
        try:
            # pad data for AES algorithm
            padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()

            # generate symmetric_key for AES algorithm using data to encrypt
            sha256 = hashlib.sha256()
            sha256.update(data)
            symmetric_key: bytes = sha256.digest()

            # encrypt padded data using AES symmetric key
            cipher = Cipher(algorithms.AES(symmetric_key), modes.ECB())
            encryptor = cipher.encryptor()
            encrypted_data: bytes = encryptor.update(padded_data) + encryptor.finalize()

            # encrypt AES symmetric key with RSA algorithm
            rsa_public_key: RSAPublicKey = serialization.load_pem_public_key(public_key)
            encrypted_symmetric_key: bytes = rsa_public_key.encrypt(
                symmetric_key,
                padding.PKCS1v15()
            )

            return struct.pack('!I', len(encrypted_symmetric_key)) + encrypted_symmetric_key + encrypted_data
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")

    def decrypt(self, private_key: PrivateKey, data: bytes) -> bytes:
        try:
            # unpack data
            uint32_size: int = 4
            if len(data) < uint32_size:
                raise DecryptionError("Not enough bytes")
            key_length: int = struct.unpack('!I', data[:uint32_size])[0]
            data_index: int = uint32_size + key_length
            if len(data) < data_index:
                raise DecryptionError("Not enough bytes")
            encrypted_symmetric_key: bytes = data[uint32_size:data_index]
            encrypted_data: bytes = data[data_index:]

            # decrypt AES symmetric key with RSA algorithm
            rsa_private_key: RSAPrivateKey = serialization.load_pem_private_key(private_key, password=None)
            decrypted_symmetric_key = rsa_private_key.decrypt(
                encrypted_symmetric_key,
                padding.PKCS1v15()
            )

            # decrypt padded data using AES symmetric key
            cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.ECB())
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # unpad decrypted data
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
            return decrypted_data
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")
