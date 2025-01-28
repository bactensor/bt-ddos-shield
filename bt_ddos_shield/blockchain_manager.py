from abc import ABC, abstractmethod
from typing import Optional

import bittensor
import bittensor_wallet
from bittensor.core.extrinsics.serving import (
    get_metadata,
    publish_metadata,
)
from bt_ddos_shield.utils import Hotkey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing address to blockchain.
    """

    def put_miner_manifest_address(self, url: str):
        """
        Put miner manifest address to blockchain.
        """
        self.put(url.encode())

    def get_miner_manifest_address(self) -> Optional[str]:
        """
        Get miner manifest address from blockchain or None if not found or not valid.
        """
        serialized_url: Optional[bytes] = self.get()
        if serialized_url is None:
            return None
        try:
            return serialized_url.decode()
        except UnicodeDecodeError:
            return None

    @abstractmethod
    def put(self, data: bytes):
        """
        Put data to blockchain for given user identified by hotkey.
        """
        pass

    @abstractmethod
    def get(self) -> Optional[bytes]:
        """
        Get data from blockchain for given user identified by hotkey or None if not found.
        """
        pass


class ReadOnlyBittensorBlockchainManager(AbstractBlockchainManager):
    """
    Read-only Bittensor BlockchainManager implementation using commitments of knowledge as storage.
    """

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        hotkey: Hotkey,
    ):
        self.subtensor = subtensor
        self.netuid = netuid
        self.hotkey = hotkey

    def get(self) -> Optional[bytes]:
        """
        Get data from blockchain for given user identified by hotkey or None if not found.
        """

        metadata = get_metadata(
            self.subtensor,
            self.netuid,
            self.hotkey,
        )

        try:
            field = metadata["info"]["fields"][0]
        except TypeError:
            return None
        except LookupError:
            return None

        try:
            value = next(iter(field.values()))
        except StopIteration:
            return None

        return bytes.fromhex(value[2:])

    def put(self, data: bytes):
        raise NotImplementedError


class BittensorBlockchainManager(ReadOnlyBittensorBlockchainManager):
    """
    Bittensor BlockchainManager implementation using commitments of knowledge as storage.
    """

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        wallet: bittensor_wallet.Wallet,
    ):
        super().__init__(
            hotkey=wallet.hotkey.ss58_address,
            netuid=netuid,
            subtensor=subtensor,
        )

        self.wallet = wallet

    def put(self, data: bytes):
        """
        Put data to blockchain for given user identified by hotkey.
        """

        publish_metadata(
            self.subtensor,
            self.wallet,
            self.netuid,
            f"Raw{len(data)}",
            data,
            wait_for_inclusion=True,
            wait_for_finalization=True,
        )
