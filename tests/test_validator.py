import asyncio
import os
from urllib.parse import urlparse

from bt_ddos_shield.address_manager import AbstractAddressManager
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldFactory
from bt_ddos_shield.state_manager import SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.utils import Hotkey
from bt_ddos_shield.validator import MinerAddress, Validator, ValidatorFactory
from tests.test_credentials import (
    aws_access_key_id,
    aws_region_name,
    aws_route53_hosted_zone_id,
    aws_s3_bucket_name,
    aws_secret_access_key,
    miner_instance_ip,
    miner_instance_port,
    sql_alchemy_db_url,
)
from tests.test_encryption_manager import generate_key_pair


class TestValidator:
    """
    Test suite for the Validator class.
    """

    MINER_HOTKEY: Hotkey = "miner"
    VALIDATOR_HOTKEY: Hotkey = "validator"

    def test_full_flow(self):
        """
        Test if validator is working using real managers and real shield.
        """
        validator_private_key, validator_public_key = generate_key_pair()
        validators = {self.VALIDATOR_HOTKEY: validator_public_key}

        os.environ["MINER_HOTKEY"] = self.MINER_HOTKEY
        os.environ["AWS_ACCESS_KEY_ID"] = aws_access_key_id
        os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret_access_key

        os.environ["VALIDATOR_HOTKEY"] = self.VALIDATOR_HOTKEY
        os.environ["VALIDATOR_PRIVATE_KEY"] = validator_private_key
        validator: Validator = ValidatorFactory.create_validator()

        os.environ["AWS_MINER_INSTANCE_IP"] = miner_instance_ip
        os.environ["MINER_INSTANCE_PORT"] = str(miner_instance_port)
        os.environ["AWS_REGION_NAME"] = aws_region_name
        os.environ["AWS_S3_BUCKET_NAME"] = aws_s3_bucket_name
        os.environ["AWS_ROUTE53_HOSTED_ZONE_ID"] = aws_route53_hosted_zone_id
        os.environ["SQL_ALCHEMY_DB_URL"] = sql_alchemy_db_url
        shield: MinerShield = MinerShieldFactory.create_miner_shield(validators)

        assert isinstance(shield.state_manager, SQLAlchemyMinerShieldStateManager)
        state_manager: SQLAlchemyMinerShieldStateManager = shield.state_manager  # type: ignore
        state_manager.clear_tables()

        address_manager: AbstractAddressManager = shield.address_manager

        # TODO: Connect blockchain managers because there is only MemoryBlockchainManager as for now
        validator._blockchain_manager = shield.blockchain_manager

        shield.enable()
        assert shield.run

        try:
            miner_address: MinerAddress = asyncio.run(asyncio.wait_for(validator.fetch_miner_address(), timeout=60))
            urlparse(miner_address.domain)
            assert miner_address.port == miner_instance_port
        finally:
            shield.disable()
            assert not shield.run
            address_manager.clean_all()
