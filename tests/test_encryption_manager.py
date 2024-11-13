import pytest
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager, EncryptionError, DecryptionError
from ecies.utils import generate_eth_key


def generate_key_pair() -> tuple[str, str]:
    """
    Generate a pair of private and public Ethereum (secp256k1) keys in hex format.
    """
    eth_k = generate_eth_key()
    private_key: str = eth_k.to_hex()
    public_key: str = eth_k.public_key.to_hex()
    return private_key, public_key


# Sample test data
valid_test_data = b"encrypted_address"
non_encrypted_bytes = b"This is not encrypted"
invalid_key = "invalid_key"


class TestEncryptionManager:
    """
    Test suite for the EncryptionManager class.
    """

    encryption_manager = ECIESEncryptionManager()
    private_key, public_key = generate_key_pair()

    def test_encrypt_data_valid(self):
        """
        Test encryption with valid public key and data.
        """
        self.encryption_manager.encrypt(public_key=self.public_key, data=valid_test_data)

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
        encrypted_data = self.encryption_manager.encrypt(public_key=self.public_key, data=valid_test_data)
        decrypted_data = self.encryption_manager.decrypt(private_key=self.private_key, data=encrypted_data)
        assert decrypted_data == valid_test_data, "Decrypted data should match the original data"

    def test_decrypt_data_invalid_private_key(self):
        """
        Test decryption with an invalid private key (string that doesn't represent a valid key).
        Expects DecryptionError to be raised.
        """
        encrypted_data = self.encryption_manager.encrypt(public_key=self.public_key, data=valid_test_data)
        with pytest.raises(DecryptionError):
            self.encryption_manager.decrypt(private_key=invalid_key, data=encrypted_data)

    def test_decrypt_data_invalid_encrypted_data(self):
        """
        Test decryption with invalid encrypted data (non-encrypted bytes).
        Expects DecryptionError to be raised.
        """
        with pytest.raises(DecryptionError):
            self.encryption_manager.decrypt(private_key=self.private_key, data=non_encrypted_bytes)
