import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from bt_ddos_shield.encryption_manager import AesRsaEncryptionManager, EncryptionError, DecryptionError


def generate_key_pair():
    """
    Generate a valid pair of public and private keys for testing.
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key: RSAPublicKey = private_key.public_key()

    private_pem: bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.PKCS8,
                                                   encryption_algorithm=serialization.NoEncryption())

    public_pem: bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return private_pem, public_pem


# Sample test data
valid_test_data = b"encrypted_address"
non_encrypted_bytes = b"This is not encrypted"
invalid_key = b"invalid_key"


class TestEncryptionManager:
    """
    Test suite for the EncryptionManager class.
    """

    encryption_manager = AesRsaEncryptionManager()
    private_pem, public_pem = generate_key_pair()

    def test_encrypt_data_valid(self):
        """
        Test encryption with valid public key and data.
        """
        self.encryption_manager.encrypt(public_key=self.public_pem, data=valid_test_data)

    def test_encrypt_data_same_result(self):
        """
        Test if consecutive encryptions generates same data.
        """
        encrypted_data1: bytes = self.encryption_manager.encrypt(public_key=self.public_pem, data=valid_test_data)
        encrypted_data2: bytes = self.encryption_manager.encrypt(public_key=self.public_pem, data=valid_test_data)
        assert encrypted_data1 == encrypted_data2, "Consecutive encryptions should generate the same data"

    def test_encrypt_data_invalid_public_key(self):
        """
        Test encryption with an invalid public key (string that doesn't represent a valid key).
        Expects EncryptionError to be raised.
        """
        with pytest.raises(EncryptionError):
            self.encryption_manager.encrypt(public_key=invalid_key, data=valid_test_data)

    def test_decrypt_data_valid(self):
        """
        Test decryption with valid private key and encrypted data.
        Ensures that the decrypted data matches the original one.
        """
        encrypted_data = self.encryption_manager.encrypt(public_key=self.public_pem, data=valid_test_data)
        decrypted_data = self.encryption_manager.decrypt(private_key=self.private_pem, data=encrypted_data)
        assert decrypted_data == valid_test_data, "Decrypted data should match the original data"

    def test_decrypt_data_invalid_private_key(self):
        """
        Test decryption with an invalid private key (string that doesn't represent a valid key).
        Expects DecryptionError to be raised.
        """
        encrypted_data = self.encryption_manager.encrypt(public_key=self.public_pem, data=valid_test_data)
        with pytest.raises(DecryptionError):
            self.encryption_manager.decrypt(private_key=invalid_key, data=encrypted_data)

    def test_decrypt_data_invalid_encrypted_data(self):
        """
        Test decryption with invalid encrypted data (non-encrypted bytes).
        Expects DecryptionError to be raised.
        """
        with pytest.raises(DecryptionError):
            self.encryption_manager.decrypt(private_key=self.private_pem, data=non_encrypted_bytes)
