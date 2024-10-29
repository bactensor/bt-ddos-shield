import json
from ecies import encrypt, decrypt


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


class EncryptionManager:

    @staticmethod
    def encrypt_data(
        public_key: str, data: dict, encoding: str = "utf-8"
    ) -> bytes:
        """
        Encrypts the given data as a dictionary using the provided public key.

        Args:
            public_key (str): The public key in string format that will be used to encrypt the data.
            data (dict): The data to be encrypted, represented as a dictionary.
            encoding (str): Encoding format for the string representation of the data (default: 'utf-8').

        Returns:
            bytes: The encrypted data in bytes format.
        """
        if not isinstance(public_key, str):
            raise TypeError(f"Public key must be of type str: {public_key}")

        if not isinstance(data, dict):
            raise TypeError(f"Data must be of type dict: {data}")

        try:
            data_str = json.dumps(data).encode(encoding=encoding)
            encrypted_data = encrypt(public_key, data_str)
            return encrypted_data
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")

    @staticmethod
    def decrypt_data(
        private_key: str, encrypted_data: bytes, encoding: str = "utf-8"
    ) -> dict:
        """
        Decrypts the given encrypted data using the provided private key.

        Args:
            private_key (str): The private key in string format used for decryption.
            encrypted_data (bytes): The encrypted data to be decrypted.
            encoding (str): Encoding format for the string representation of the data (default: 'utf-8').

        Returns:
            dict: The decrypted data, converted back to a dictionary.
        """
        if not isinstance(private_key, str):
            raise TypeError(f"Private key must be of type str: {private_key}")

        if not isinstance(encrypted_data, bytes):
            raise TypeError(f"Encrypted data must be of type bytes: {encrypted_data}")

        try:
            decrypted_data = decrypt(private_key, encrypted_data)
            decrypted_str = decrypted_data.decode(encoding=encoding)
            decrypted_dict = json.loads(decrypted_str)
            return decrypted_dict
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")
