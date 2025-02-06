import asyncio
from urllib.parse import urlparse, ParseResult

import bittensor_wallet
from bt_ddos_shield.address_manager import AbstractAddressManager
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldFactory
from bt_ddos_shield.state_manager import SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.utils import Hotkey
from bt_ddos_shield.shield_metagraph import ShieldMetagraph
from tests.conftest import ShieldTestSettings


class TestValidator:
    """
    Test suite for the Validator class.
    """

    def test_full_flow(self, shield_settings: ShieldTestSettings):
        """
        Test if validator is working using real managers and real shield.

        IMPORTANT: Test can run for many minutes due to AWS delays.
        """
        validator_wallet: bittensor_wallet.Wallet = shield_settings.validator_wallet.instance
        metagraph: ShieldMetagraph = ShieldMetagraph(
            wallet=validator_wallet,
            private_key=shield_settings.validator_private_key,
            subtensor=shield_settings.subtensor.create_client(),
            netuid=shield_settings.netuid,
        )

        validator_hotkey: Hotkey = validator_wallet.hotkey.ss58_address
        validators = {validator_hotkey}
        shield: MinerShield = MinerShieldFactory.create_miner_shield(shield_settings, validators)

        assert isinstance(shield.state_manager, SQLAlchemyMinerShieldStateManager)
        state_manager: SQLAlchemyMinerShieldStateManager = shield.state_manager  # type: ignore
        state_manager.clear_tables()

        address_manager: AbstractAddressManager = shield.address_manager

        shield.enable()
        assert shield.run

        shield.task_queue.join()

        try:
            miner_hotkey: str = shield_settings.wallet.instance.hotkey.ss58_address
            miner_url: str = asyncio.run(asyncio.wait_for(metagraph.fetch_miner_address(miner_hotkey),
                                                          timeout=20))
            parsed_url: ParseResult = urlparse('http://' + miner_url)
            assert parsed_url.port == shield_settings.miner_instance_port
        finally:
            shield.disable()
            assert not shield.run
            address_manager.clean_all()
