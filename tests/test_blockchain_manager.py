import threading
import unittest.mock
from typing import Optional

import pytest
import websockets.exceptions

from bt_ddos_shield.blockchain_manager import (
    AbstractBlockchainManager,
    BittensorBlockchainManager,
)
from bt_ddos_shield.utils import Hotkey


class MemoryBlockchainManager(AbstractBlockchainManager):
    known_data: dict[Hotkey, bytes]
    put_counter: int

    def __init__(self, miner_hotkey: Hotkey):
        self.miner_hotkey = miner_hotkey
        self.known_data = {}
        self.put_counter = 0
        self._lock = threading.Lock()

    def get_own_manifest_url(self) -> Optional[str]:
        return self.get_manifest_url(self.miner_hotkey)

    def put_metadata(self, data: bytes):
        with self._lock:
            self.known_data[self.miner_hotkey] = data
            self.put_counter += 1

    def get_metadata(self, hotkey: Hotkey) -> Optional[bytes]:
        with self._lock:
            return self.known_data.get(self.miner_hotkey)


@pytest.fixture
def wallet_hotkey():
    return "5EU2xVWC7qffsUNGtvakp5WCj7WGJMPkwG1dsm3qnU2Kqvee"


@pytest.fixture
def wallet(wallet_hotkey):
    mock_wallet = unittest.mock.Mock()
    mock_wallet.hotkey.ss58_address = wallet_hotkey
    return mock_wallet


def test_bittensor_get(wallet):
    mock_subtensor = unittest.mock.MagicMock()
    mock_substrate = mock_subtensor.substrate.__enter__.return_value
    mock_substrate.query.return_value = unittest.mock.Mock(
        value={
            "info": {
                "fields": None,
            },
        },
    )

    manager = BittensorBlockchainManager(
        subtensor=mock_subtensor,
        wallet=wallet,
        netuid=1,
        event_processor=unittest.mock.Mock(),
    )

    assert manager.get_metadata(manager.get_hotkey()) is None

    mock_substrate.query.assert_called_once_with(
        module="Commitments",
        storage_function="CommitmentOf",
        params=[1, "5EU2xVWC7qffsUNGtvakp5WCj7WGJMPkwG1dsm3qnU2Kqvee"],
        block_hash=None,
    )

    mock_substrate.query.reset_mock()
    mock_substrate.query.return_value = unittest.mock.Mock(
        value={
            "info": {
                "fields": [
                    {
                        "Raw4": "0x64617461",
                    },
                ],
            },
        },
    )

    assert manager.get_metadata(manager.get_hotkey()) == b"data"


def test_bittensor_put(wallet):
    mock_subtensor = unittest.mock.MagicMock()
    mock_substrate = mock_subtensor.substrate.__enter__.return_value

    manager = BittensorBlockchainManager(
        subtensor=mock_subtensor,
        wallet=wallet,
        netuid=1,
        event_processor=unittest.mock.Mock(),
    )

    manager.put_metadata(b"data")

    mock_substrate.compose_call.assert_called_once_with(
        call_module="Commitments",
        call_function="set_commitment",
        call_params={
            "netuid": 1,
            "info": {
                "fields": [
                    [
                        {
                            "Raw4": b"data",
                        },
                    ],
                ],
            },
        },
    )
    mock_substrate.create_signed_extrinsic.assert_called_once_with(
        call=mock_substrate.compose_call.return_value,
        keypair=wallet.hotkey,
    )
    mock_subtensor.substrate.submit_extrinsic.assert_called_once_with(
        mock_substrate.create_signed_extrinsic.return_value,
        wait_for_inclusion=True,
        wait_for_finalization=True,
    )


def test_bittensor_retries(wallet):
    mock_subtensor = unittest.mock.MagicMock()
    mock_substrate = mock_subtensor.substrate.__enter__.return_value
    mock_substrate.query.side_effect = (
        websockets.exceptions.ConnectionClosed(None, None),
        unittest.mock.Mock(
            value={
                "info": {
                    "fields": [
                        {
                            "Raw4": "0x64617461",
                        },
                    ],
                },
            },
        ),
    )

    manager = BittensorBlockchainManager(
        subtensor=mock_subtensor,
        wallet=wallet,
        netuid=1,
        event_processor=unittest.mock.Mock(),
    )

    assert manager.get_metadata(manager.get_hotkey()) == b"data"
    assert mock_substrate.query.call_count == 2

    mock_subtensor.substrate.submit_extrinsic.side_effect = (
        websockets.exceptions.ConnectionClosed(None, None),
        unittest.mock.Mock(),
    )

    manager.put_metadata(b"data")

    assert mock_subtensor.substrate.submit_extrinsic.call_count == 2
