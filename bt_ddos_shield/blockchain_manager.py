from abc import ABC, abstractmethod
from typing import Optional

import bittensor
import bittensor_wallet
from bittensor.core.extrinsics.serving import (
    publish_metadata,
)
from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
from bt_ddos_shield.utils import Hotkey


class BlockchainManagerException(Exception):
    pass


class AbstractBlockchainManager(ABC):
    """
    Abstract base class for manager handling publishing manifest address to blockchain.
    """

    def put_manifest_url(self, url: str):
        """
        Put manifest url to blockchain for wallet owner.
        """
        self.put_metadata(url.encode())

    async def get_manifest_url(self, hotkey: Hotkey) -> Optional[str]:
        """
        Get manifest url for given neuron identified by hotkey. Returns None if url is not found.
        """
        serialized_url: Optional[bytes] = await self.get_metadata(hotkey)
        if serialized_url is None:
            return None
        try:
            return serialized_url.decode()
        except UnicodeDecodeError:
            return None

    async def get_own_manifest_url(self) -> Optional[str]:
        """
        Get manifest url for wallet owner. Returns None if url is not found.
        """
        return await self.get_manifest_url(self.get_hotkey())

    @abstractmethod
    def put_metadata(self, data: bytes):
        """
        Put neuron metadata to blockchain for wallet owner.
        """
        pass

    @abstractmethod
    async def get_metadata(self, hotkey: Hotkey) -> Optional[bytes]:
        """
        Get metadata from blockchain for given neuron identified by hotkey. Returns None if metadata is not found.
        """
        pass

    @abstractmethod
    def get_hotkey(self) -> Hotkey:
        """ Returns hotkey of the wallet owner. """
        pass


class BittensorBlockchainManager(AbstractBlockchainManager):
    """
    Bittensor BlockchainManager implementation using commitments of knowledge as storage.
    """

    subtensor: bittensor.Subtensor
    netuid: int
    wallet: bittensor_wallet.Wallet
    event_processor: AbstractMinerShieldEventProcessor

    def __init__(
            self,
            subtensor: bittensor.Subtensor,
            netuid: int,
            wallet: bittensor_wallet.Wallet,
            event_processor: AbstractMinerShieldEventProcessor,
    ):
        self.subtensor = subtensor
        self.netuid = netuid
        self.wallet = wallet
        self.event_processor = event_processor

    async def get_metadata(self, hotkey: Hotkey) -> Optional[bytes]:
        try:
            async with bittensor.AsyncSubtensor(self.subtensor.chain_endpoint) as async_subtensor:
                metadata: dict = await async_subtensor.substrate.query(
                    module="Commitments",
                    storage_function="CommitmentOf",
                    params=[self.netuid, hotkey],
                )
        except Exception as e:
            self.event_processor.event('Failed to get metadata for netuid={netuid}, hotkey={hotkey}',
                                       exception=e, netuid=self.netuid, hotkey=hotkey)
            raise BlockchainManagerException(f'Failed to get metadata: {e}') from e

        try:
            # This structure is hardcoded in bittensor publish_metadata function, but corresponding get_metadata
            # function does not use it, so we need to extract the value manually.

            # Commented parts of the code shows how this extraction should look if async version will work properly,
            # the same as sync version does. Now async version doesn't decode raw SCALE objects properly. I left this
            # code as it will be easier one day to restore this proper parsing.
            # fields: list[dict[str, str]] = metadata["info"]["fields"]
            fields = metadata["info"]["fields"]

            # As for now there is only one field in metadata. Field contains map from type of data to data itself.
            # field: dict[str, str] = fields[0]
            field = fields[0][0]

            # Find data of 'Raw' type.
            for data_type, data in field.items():
                if data_type.startswith('Raw'):
                    break
            else:
                return None

            # Raw data is hex-encoded and prefixed with '0x'.
            # return bytes.fromhex(data[2:])
            return bytes(data[0])
        except TypeError:
            return None
        except LookupError:
            return None

    def put_metadata(self, data: bytes):
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
