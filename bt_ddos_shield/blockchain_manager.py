from abc import ABC, abstractmethod
from typing import Optional

import bittensor
import bittensor_wallet
from bittensor.core.extrinsics.serving import (
    get_metadata,
    publish_metadata,
)
from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
from bt_ddos_shield.utils import Hotkey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing address to blockchain.
    """

    def put_manifest_url(self, url: str):
        """
        Put manifest url to blockchain for wallet owner.
        """
        self.put_metadata(url.encode())

    def get_manifest_url(self, hotkey: Hotkey) -> Optional[str]:
        """
        Get manifest url for given neuron identified by hotkey. Returns None if url is not found.
        """
        serialized_url: Optional[bytes] = self.get_metadata(hotkey)
        if serialized_url is None:
            return None
        try:
            return serialized_url.decode()
        except UnicodeDecodeError:
            return None

    @abstractmethod
    def put_metadata(self, data: bytes):
        """
        Put neuron metadata to blockchain for wallet owner.
        """
        pass

    @abstractmethod
    def get_metadata(self, hotkey: Hotkey) -> Optional[bytes]:
        """
        Get metadata from blockchain for given neuron identified by hotkey. Returns None if metadata is not found.
        """
        pass

    @abstractmethod
    def get_own_manifest_url(self) -> Optional[str]:
        """
        Get manifest url for wallet owner. Returns None if url is not found.
        """
        pass


class ReadOnlyBittensorBlockchainManager(AbstractBlockchainManager):
    """
    Read-only Bittensor BlockchainManager implementation using commitments of knowledge as storage.
    """

    subtensor: bittensor.Subtensor
    netuid: int
    event_processor: AbstractMinerShieldEventProcessor

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        event_processor: AbstractMinerShieldEventProcessor,
    ):
        self.subtensor = subtensor
        self.netuid = netuid
        self.event_processor = event_processor

    def get_metadata(self, hotkey: Hotkey) -> Optional[bytes]:
        try:
            metadata: dict = get_metadata(  # type: ignore
                self.subtensor,
                self.netuid,
                hotkey,
            )
        except Exception as e:
            self.event_processor.event('Failed to get metadata for netuid={netuid}, hotkey={hotkey}',
                                       exception=e, netuid=self.netuid, hotkey=hotkey)
            raise BlockchainManagerException(f'Failed to get metadata: {e}') from e

        try:
            # This structure is hardcoded in bittensor publish_metadata function, but corresponding get_metadata
            # function does not use it, so we need to extract the value manually.
            fields: list[dict[str, str]] = metadata["info"]["fields"]

            # As for now there is only one field in metadata. Field contains map from type of data to data itself.
            field: dict[str, str] = fields[0]

            # Find data of 'Raw' type.
            for data_type, data in field.items():
                if data_type.startswith('Raw'):
                    break
            else:
                return None

            # Raw data is hex-encoded and prefixed with '0x'.
            return bytes.fromhex(data[2:])
        except TypeError:
            return None
        except LookupError:
            return None

    def get_own_manifest_url(self) -> Optional[str]:
        raise NotImplementedError

    def put_metadata(self, data: bytes):
        raise NotImplementedError


class BittensorBlockchainManager(ReadOnlyBittensorBlockchainManager):
    """
    Bittensor BlockchainManager implementation using commitments of knowledge as storage.
    """

    wallet: bittensor_wallet.Wallet

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        wallet: bittensor_wallet.Wallet,
        event_processor: AbstractMinerShieldEventProcessor,
    ):
        super().__init__(
            netuid=netuid,
            subtensor=subtensor,
            event_processor=event_processor,
        )

        self.wallet = wallet

    def put_metadata(self, data: bytes):
        """
        Put data to blockchain for given user identified by hotkey.
        """

        try:
            publish_metadata(
                self.subtensor,
                self.wallet,
                self.netuid,
                data_type=f'Raw{len(data)}',
                data=data,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except Exception as e:
            self.event_processor.event('Failed to publish metadata for netuid={netuid}, wallet={wallet}',
                                       exception=e, netuid=self.netuid, wallet=str(self.wallet))
            raise BlockchainManagerException(f'Failed to publish metadata: {e}') from e

    def get_hotkey(self) -> Hotkey:
        return self.wallet.hotkey.ss58_address

    def get_own_manifest_url(self) -> Optional[str]:
        return self.get_manifest_url(self.get_hotkey())
