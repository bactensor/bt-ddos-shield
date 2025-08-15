from __future__ import annotations

import os

from bt_ddos_shield.certificate_manager import (
    Certificate,
    EDDSACertificateManager,
)


class TestCertificateManager:
    """
    Test suite for the EDDSACertificateManager class.
    """

    certificate_manager = EDDSACertificateManager()

    def test_generate_certificate(self):
        """
        Test certificate generation.
        """
        certificate = self.certificate_manager.generate_certificate()
        assert isinstance(certificate, Certificate)
        assert certificate.private_key is not None
        assert certificate.public_key is not None

    def test_save_and_load_certificate(self) -> None:
        """
        Test saving and loading a certificate to/from disk.
        """
        path: str = 'certificate_test.pem'
        certificate: Certificate = self.certificate_manager.generate_certificate()
        try:
            self.certificate_manager.save_certificate(certificate, path)
            loaded_certificate: Certificate = self.certificate_manager.load_certificate(path)
            assert certificate.private_key == loaded_certificate.private_key
            assert certificate.public_key == loaded_certificate.public_key
            assert certificate.algorithm == loaded_certificate.algorithm
        finally:
            os.remove(path)
