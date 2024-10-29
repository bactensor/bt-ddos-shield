import pytest

from bt_ddos_shield.encryption import (
    EncryptionManager,
    EncryptionError,
    DecryptionError,
)
from ecies.utils import generate_eth_key

# Generate a valid pair of public and private keys for testing
eth_k = generate_eth_key()
private_key = eth_k.to_hex()
public_key = eth_k.public_key.to_hex()

# Sample test data
valid_test_data = {
    "name": "John",
    "age": 32,
    "github": {"login": "John", "events": [1, 2, 3]},
}
empty_data_dict = {}
non_encrypted_bytes = b"This is not encrypted"
empty_byte = b""
invalid_key_type = 123
invalid_string_data = "invalid_data"

# Pre-encrypt valid data for decryption tests.
pre_encrypted_data = EncryptionManager.encrypt_data(
    public_key=public_key, data=valid_test_data
)


class TestEncryptionManager:
    """
    Test suite for the EncryptionManager class.
    """

    def test_encrypt_data_valid(self):
        """
        Test encryption with valid public key and data.
        Ensures the returned encrypted data is of bytes type.
        """
        encrypted_data = EncryptionManager.encrypt_data(
            public_key=public_key, data=valid_test_data
        )
        assert isinstance(
            encrypted_data, bytes
        ), "Encrypted dta should be of type bytes"

    def test_encrypt_data_invalid_public_key(self):
        """
        Test encryption with an invalid public key (string that doesn't represent a valid key).
        Expects EncryptionError to be raised.
        """
        with pytest.raises(EncryptionError):
            EncryptionManager.encrypt_data(
                public_key=invalid_string_data, data=valid_test_data
            )

    def test_encrypt_data_invalid_data_type(self):
        """
        Test encryption with an invalid data type (non-dict data).
        Expects TypeError to be raised.
        """
        with pytest.raises(TypeError):
            EncryptionManager.encrypt_data(
                public_key=public_key, data=invalid_string_data
            )

    def test_encrypt_data_invalid_public_key_type(self):
        """
        Test encryption with a public key of invalid type (e.g., integer).
        Expects TypeError to be raised.
        """
        with pytest.raises(TypeError):
            EncryptionManager.encrypt_data(
                public_key=invalid_key_type, data=valid_test_data
            )

    def test_encrypt_data_empty_data(self):
        """
        Test encryption with an empty dictionary.
        Expects encryption to succeed and return data of type bytes.
        """
        encrypted_empty_data = EncryptionManager.encrypt_data(
            public_key=public_key, data=empty_data_dict
        )
        assert isinstance(
            encrypted_empty_data, bytes
        ), "Encrypted data should be of type bytes for an empty dict"

    def test_decrypt_data_valid(self):
        """
        Test decryption with valid private key and encrypted data.
        Ensures that the decrypted data matches the original dictionary.
        """
        decrypted_data = EncryptionManager.decrypt_data(
            private_key=private_key, encrypted_data=pre_encrypted_data
        )
        assert isinstance(decrypted_data, dict), "Decrypted data should be of type dict"
        assert (
            decrypted_data == valid_test_data
        ), "Decrypted data should match the original data"

    def test_decrypt_data_empty_data(self):
        """
        Test decryption with an empty dictionary.
        Expects that the decrypted data matches the original dictionary.
        """
        encrypted_empty_data = EncryptionManager.encrypt_data(
            public_key=public_key, data=empty_data_dict
        )
        decrypted_data = EncryptionManager.decrypt_data(
            private_key=private_key, encrypted_data=encrypted_empty_data
        )
        assert isinstance(decrypted_data, dict), "Decrypted data should be of type dict"
        assert (
            decrypted_data == empty_data_dict
        ), "Decrypted data should match the original data"

    def test_decrypt_data_invalid_private_key(self):
        """
        Test decryption with an invalid private key (string that doesn't represent a valid key).
        Expects DecryptionError to be raised.
        """
        with pytest.raises(DecryptionError):
            EncryptionManager.decrypt_data(
                private_key=invalid_string_data, encrypted_data=pre_encrypted_data
            )

    def test_decrypt_data_invalid_encrypted_data(self):
        """
        Test decryption with invalid encrypted data (non-encrypted bytes).
        Expects DecryptionError to be raised.
        """
        with pytest.raises(DecryptionError):
            EncryptionManager.decrypt_data(
                private_key=private_key, encrypted_data=non_encrypted_bytes
            )

    def test_decrypt_data_invalid_private_key_type(self):
        """
        Test decryption with a private key of invalid type (e.g., integer).
        Expects TypeError to be raised.
        """
        with pytest.raises(TypeError):
            EncryptionManager.decrypt_data(
                private_key=invalid_key_type, encrypted_data=pre_encrypted_data
            )

    def test_decrypt_data_invalid_encrypted_data_type(self):
        """
        Test decryption with encrypted data of invalid type (e.g., integer).
        Expects TypeError to be raised.
        """
        with pytest.raises(TypeError):
            EncryptionManager.decrypt_data(
                private_key=private_key, encrypted_data=invalid_key_type
            )

    def test_decrypt_data_empty_encrypted_data(self):
        """
        Test decryption with empty encrypted data (empty byte string).
        Expects DecryptionError to be raised.
        """
        with pytest.raises(DecryptionError):
            EncryptionManager.decrypt_data(
                private_key=private_key, encrypted_data=empty_byte
            )
