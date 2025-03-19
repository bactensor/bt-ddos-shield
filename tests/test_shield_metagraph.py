from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from bt_ddos_shield.miner_shield import MinerShield, MinerShieldFactory
from bt_ddos_shield.shield_metagraph import ShieldMetagraph
from bt_ddos_shield.state_manager import SQLAlchemyMinerShieldStateManager
from bt_ddos_shield.validators_manager import BittensorValidatorsManager

if TYPE_CHECKING:
    from bittensor.core.chain_data import AxonInfo

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
        miner_hotkey: str = shield_settings.wallet.instance.hotkey.ss58_address

        # We need to add any validator to set, otherwise manifest addresses will be created for all validators in
        # network including tested validator, what we don't want
        validators = {'unknown_hotkey'}
        shield: MinerShield = MinerShieldFactory.create_miner_shield(shield_settings, validators)

        assert isinstance(shield.state_manager, SQLAlchemyMinerShieldStateManager)
        state_manager: SQLAlchemyMinerShieldStateManager = shield.state_manager
        state_manager.clear_tables()

        assert isinstance(shield.validators_manager, BittensorValidatorsManager)
        validators_manager: BittensorValidatorsManager = shield.validators_manager

        shield.enable()
        assert shield.run
        shield.task_queue.join()  # Wait for full shield initialization - should create empty manifest

        try:
            metagraph: ShieldMetagraph = ShieldMetagraph(
                wallet=shield_settings.validator_wallet.instance,
                subtensor=shield_settings.subtensor.create_client(),
                netuid=shield_settings.netuid,
            )
            miner_axon: AxonInfo = next(axon for axon in metagraph.axons if axon.hotkey == miner_hotkey)

            shield.disable()
            validators_manager.validators = frozenset()
            shield.enable()
            shield.task_queue.join()  # Wait for full shield initialization - should add validator to manifest

            metagraph.sync()
            shielded_miner_axon: AxonInfo = next(axon for axon in metagraph.axons if axon.hotkey == miner_hotkey)
            assert shielded_miner_axon.ip != miner_axon.ip
            assert shielded_miner_axon.port == shield_settings.miner_instance_port
        finally:
            shield.disable()
            assert not shield.run
            shield.address_manager.clean_all()

    def test_copy(self, shield_settings: ShieldTestSettings):
        metagraph: ShieldMetagraph = ShieldMetagraph(
            wallet=shield_settings.validator_wallet.instance,
            subtensor=shield_settings.subtensor.create_client(),
            netuid=shield_settings.netuid,
        )

        metagraph_copy: ShieldMetagraph = copy.deepcopy(metagraph)
        assert metagraph_copy.axons == metagraph.axons
        assert metagraph.subtensor is not None
        assert metagraph_copy.subtensor is None, 'Metagraph class ignores subtensor field during deepcopy'

        metagraph_copy = copy.copy(metagraph)
        assert metagraph_copy.axons == metagraph.axons
        assert metagraph.subtensor is not None
        assert metagraph_copy.subtensor is None, 'Metagraph class ignores subtensor field during copy'
