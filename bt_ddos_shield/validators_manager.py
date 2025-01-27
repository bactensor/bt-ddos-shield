from abc import ABC, abstractmethod
import enum
from types import MappingProxyType
from typing import Iterable

import bittensor

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

    class CertificateAlgorithmEnum(enum.IntEnum):
        SECP256K1 = 4

    MIN_VALIDATOR_STAKE = 1000

    def __init__(
        self,
        subtensor: bittensor.Subtensor,
        netuid: int,
        validators: Iterable[Hotkey] = None,
    ):
        self.subtensor = subtensor
        self.netuid = netuid
        self.validators = frozenset(validators or [])
        self.certificates = {}

    def get_validators(self) -> MappingProxyType[Hotkey, PublicKey]:
        return MappingProxyType(self.certificates)

    def reload_validators(self):
        if self.validators:
            validators = self.validators
        else:
            neurons = self.subtensor.neurons_lite(
                self.netuid,
            )
            validators = frozenset(
                neuron.hotkey for neuron in neurons if self.is_validator(neuron)
            )

        self.certificates = self.fetch_certificates(validators)

    def fetch_certificates(
        self, validators: frozenset[Hotkey]
    ) -> dict[Hotkey, PublicKey]:
        """
        Fetch Validators' Certificates (PublicKey) from Subtensor.

        Args:
            validators: frozenset of Hotkeys.
        """

        certificates = self.subtensor.query_map(
            module="SubtensorModule",
            name="NeuronCertificates",
            params=[self.netuid],
        )
        certificates = {
            hotkey.serialize(): certificate.serialize()
            for hotkey, certificate in certificates
        }

        return {
            hotkey: certificate["public_key"][2:]
            for hotkey, certificate in certificates.items()
            if hotkey in validators
            and certificate["algorithm"]
            == BittensorValidatorsManager.CertificateAlgorithmEnum.SECP256K1
        }

    def is_validator(self, neuron: bittensor.NeuronInfoLite) -> bool:
        """
        Determine whether provided Neuron is a Validator or not.

        Args:
            neuron: Neuron to test.
        """

        return neuron.stake >= self.MIN_VALIDATOR_STAKE
