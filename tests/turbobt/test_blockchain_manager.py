from unittest.mock import Mock

from bt_ddos_shield.turbobt.blockchain_manager import (
    TurboBittensorBlockchainManager,
)


class TestTurboBittensorBlockchainManager:
    def test_get_hotkey(self):
        mock_wallet = Mock()
        mock_wallet.hotkey.ss58_address = '5HotKeyAddress123'

        manager = TurboBittensorBlockchainManager(
            bittensor=Mock(),
            netuid=1,
            wallet=mock_wallet,
            event_processor=Mock(),
        )

        assert manager.get_hotkey() == '5HotKeyAddress123'
