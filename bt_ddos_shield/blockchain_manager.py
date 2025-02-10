import asyncio
from abc import ABC, abstractmethod
from typing import Optional, Iterable, Dict, Any

import bittensor
import bittensor_wallet
from bittensor.core.chain_data.neuron_info import NeuronInfo
from bittensor.core.extrinsics.serving import (
    publish_metadata,
    serve_extrinsic,
)
from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
from bt_ddos_shield.utils import Hotkey, PublicKey
from scalecodec.base import ScaleType


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

    async def get_manifest_urls(self, hotkeys: Iterable[Hotkey]) -> Dict[Hotkey, Optional[str]]:
        """
        Get manifest urls for given neurons identified by hotkeys.
        Returns dictionary with urls for given neurons, filled with None if url is not found.
        """
        serialized_urls: Dict[Hotkey, Optional[bytes]] = await self.get_metadata(hotkeys)
        deserialized_urls: Dict[Hotkey, Optional[str]] = {}
        for hotkey, serialized_url in serialized_urls.items():
            url: Optional[str] = None
            if serialized_url is not None:
                try:
                    url = serialized_url.decode()
                except UnicodeDecodeError:
                    pass
            deserialized_urls[hotkey] = url
        return deserialized_urls

    async def get_own_manifest_url(self) -> Optional[str]:
        """
        Get manifest url for wallet owner. Returns None if url is not found.
        """
        own_hotkey: Hotkey = self.get_hotkey()
        urls: Dict[Hotkey, Optional[str]] = await self.get_manifest_urls([own_hotkey])
        return urls.get(own_hotkey)

    @abstractmethod
    def put_metadata(self, data: bytes):
        """
        Put neuron metadata to blockchain for wallet owner.
        """
        pass

    @abstractmethod
    async def get_metadata(self, hotkeys: Iterable[Hotkey]) -> Dict[Hotkey, Optional[bytes]]:
        """
        Get metadata from blockchain for given neurons identified by hotkeys.
        Returns dictionary with metadata for given neurons, filled with None if metadata is not found.
        """
        pass

    @abstractmethod
    def get_hotkey(self) -> Hotkey:
        """ Returns hotkey of the wallet owner. """
        pass

    @abstractmethod
    def get_own_public_key(self) -> PublicKey:
        """ Returns public key for wallet owner. """
        pass

    @abstractmethod
    def upload_public_key(self, public_key: PublicKey):
        """ Uploads public key to blockchain for wallet owner. """
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

    async def get_metadata(self, hotkeys: Iterable[Hotkey]) -> Dict[Hotkey, Optional[bytes]]:
        try:
            async with bittensor.AsyncSubtensor(self.subtensor.chain_endpoint) as async_subtensor:
                tasks = [self.get_single_metadata(async_subtensor, hotkey) for hotkey in hotkeys]
                results = await asyncio.gather(*tasks)
            return dict(zip(hotkeys, results))
        except Exception as e:
            self.event_processor.event('Failed to get metadata for netuid={netuid}',
                                       exception=e, netuid=self.netuid)
            raise BlockchainManagerException(f'Failed to get metadata: {e}') from e

    async def get_single_metadata(self, async_subtensor: bittensor.AsyncSubtensor, hotkey: Hotkey) -> Optional[bytes]:
        metadata: dict = await async_subtensor.substrate.query(
            module="Commitments",
            storage_function="CommitmentOf",
            params=[self.netuid, hotkey],
        )

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

    def get_own_public_key(self) -> Optional[PublicKey]:
        certificate: ScaleType = self.subtensor.query_subtensor(
            name="NeuronCertificates",
            params=[self.netuid, self.get_hotkey()],
        )
        cert_value: Optional[dict[str, Any]] = certificate.serialize()
        if cert_value is None or 'public_key' not in cert_value:
            return None
        cert_type: str = format(cert_value['algorithm'], '02x')
        return cert_type + cert_value['public_key'][2:]  # public_key is prefixed with '0x'

    def upload_public_key(self, public_key: PublicKey):
        try:
            # As for now there is no method for uploading only certificate to Subtensor, so we need to use
            # serve_extrinsic function. Because of that we need to get current neuron info to not overwrite existing
            # data - if there is not existing data, we will use default dummy values.
            neuron: Optional[NeuronInfo] = self.subtensor.get_neuron_for_pubkey_and_subnet(
                self.wallet.hotkey.ss58_address, netuid=self.netuid
            )
            new_ip: str = neuron.axon_info.ip if neuron is not None else '127.0.0.1'
            new_port: int = neuron.axon_info.port if neuron is not None else 1
            new_protocol: int = neuron.axon_info.protocol if neuron is not None else 0
            # We need to change any field, otherwise extrinsic will not be sent, so use placeholder1 (increased by 1
            # and modulo 256 as it is u8 field) to not modify any real data.
            new_placeholder1: int = (neuron.axon_info.placeholder1 + 1) % 256 if neuron is not None else 0
            # certificate param is of str type in library, but actually we need to pass bytes there
            certificate_data: bytes = bytes.fromhex(public_key)

            serve_extrinsic(
                self.subtensor,
                self.wallet,
                new_ip,
                new_port,
                new_protocol,
                self.netuid,
                certificate=certificate_data,  # type: ignore
                placeholder1=new_placeholder1,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except Exception as e:
            self.event_processor.event('Failed to upload public key for netuid={netuid}, wallet={wallet}',
                                       exception=e, netuid=self.netuid, wallet=str(self.wallet))
            raise BlockchainManagerException(f'Failed to upload public key: {e}') from e
