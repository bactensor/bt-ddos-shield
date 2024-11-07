import pytest
from time import sleep

from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor
from bt_ddos_shield.miner_shield import MinerShield, MinerShieldOptions


class TestMinerShield:
    """
    Test suite for the MinerShield class.
    """

    def test_start_stop(self):
        """
        Test if shield is properly starting and stopping.
        """
        shield = MinerShield(None,None, None, None, None,
                             None, PrintingMinerShieldEventProcessor(), MinerShieldOptions(retry_delay=1))
        shield.enable()
        assert shield.run
        sleep(1)
        shield.disable()
        assert not shield.run
