from __future__ import annotations

from abc import ABC, abstractmethod
from types import MappingProxyType
from typing import TYPE_CHECKING

from async_substrate_interface.types import ScaleObj
from bittensor.core.chain_data import decode_account_id

from bt_ddos_shield.encryption_manager import CertificateAlgorithmEnum
from bt_ddos_shield.utils import SubtensorCertificate, decode_subtensor_certificate_info

if TYPE_CHECKING:
    from collections.abc import Iterable

    import bittensor
    from async_substrate_interface.sync_substrate import QueryMapResult
    from bittensor import Balance, MetagraphInfo

    from bt_ddos_shield.utils import Hotkey, PublicKey


class AbstractValidatorsManager(ABC):
    """
    Abstract base class for manager of validators and their public keys used for encryption.
    """

    @abstractmethod
    def get_validators(self) -> MappingProxyType[Hotkey, PublicKey]:
        """
        Get cached dictionary of validators.

        Returns:
            dict[Hotkey, PublicKey]: Mapping HotKey of validator -> his public key.
        """
        pass

    @abstractmethod
    def reload_validators(self):
        """
        Reload validators dictionary. Blocks code execution until new validators set is fetched.
        """
        pass


class MemoryValidatorsManager(AbstractValidatorsManager):
    """
    Validators manager implementation which stores fixed validators in memory.
    """

    validators: dict[Hotkey, PublicKey]

    def __init__(self, validators: dict[Hotkey, PublicKey]):
        self.validators = dict(validators)

    def get_validators(self) -> MappingProxyType[Hotkey, PublicKey]:
        return MappingProxyType(self.validators)

    def reload_validators(self):
        pass


class BittensorValidatorsManager(AbstractValidatorsManager):
    """
    Validators Manager using Bittensor Neurons' Certificates.
    """

    # Having total stake of 1000 alpha tokens is needed to set weights, and it is minimal value for shield to treat
    # neuron as validator. It is simple heuristic, which can be not valid for all subnets, but as for now is sufficient.
    MIN_VALIDATOR_STAKE = 1000

    # Only top 64 neurons are treat by Subtensor as validators. It is a heuristic, which can be not valid for all
    # subnets, but as for now is sufficient.
    VALIDATORS_COUNT_THRESHOLD = 64

    subtensor: bittensor.Subtensor
    netuid: int
    validators: frozenset[Hotkey]
    certificates: dict[Hotkey, PublicKey]

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        validators: Iterable[Hotkey] | None = None,
    ):
        self.subtensor = subtensor
        self.netuid = netuid
        self.validators = frozenset(validators or [])
        self.certificates = {}

    def get_validators(self) -> MappingProxyType[Hotkey, PublicKey]:
        return MappingProxyType(self.certificates)

    def reload_validators(self) -> None:
        validators: frozenset[Hotkey]
        if self.validators:
            validators = self.validators
        else:
            validators = self.get_validators_from_metagraph()

        self.certificates = self.fetch_certificates(validators)

    def fetch_certificates(self, validators: frozenset[Hotkey]) -> dict[Hotkey, PublicKey]:
        """
        Fetch Validators' Certificates (PublicKey) from Subtensor for given validators identified by hotkeys.
        """
        query_certificates: QueryMapResult = self.subtensor.query_map(
            module='SubtensorModule',
            name='NeuronCertificates',
            params=[self.netuid],
        )
        certificates: dict[Hotkey, SubtensorCertificate | None] = {
            decode_account_id(chain_hotkey): decode_subtensor_certificate_info(chain_certificate.value)
            for chain_hotkey, chain_certificate in query_certificates
            if isinstance(chain_certificate, ScaleObj)
        }
        return {
            hotkey: certificate.hex_data
            for hotkey, certificate in certificates.items()
            if hotkey in validators
            and certificate is not None
            and certificate.algorithm == CertificateAlgorithmEnum.ECDSA_SECP256K1_UNCOMPRESSED
        }

    def get_validators_from_metagraph(self) -> frozenset[Hotkey]:
        """
        Default logic for determining validators set.
        """
        info: MetagraphInfo | None = self.subtensor.get_metagraph_info(self.netuid)
        assert info is not None, 'Can be None only if Subnet netuid is invalid'
        sorted_neurons: list[tuple[Hotkey, Balance]] = sorted(
            zip(info.hotkeys, info.total_stake, strict=True), key=lambda x: x[1].tao, reverse=True
        )
        top_neurons: list[tuple[Hotkey, Balance]] = sorted_neurons[: self.VALIDATORS_COUNT_THRESHOLD]
        return frozenset(hotkey for hotkey, stake in top_neurons if stake.tao >= self.MIN_VALIDATOR_STAKE)
