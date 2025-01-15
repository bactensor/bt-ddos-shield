import pytest

from bt_ddos_shield.miner_shield import ShieldSettings
from bt_ddos_shield.validator import ValidatorSettings


class ShieldTestSettings(ShieldSettings):
    aws_route53_other_hosted_zone_id: str

    model_config = {
        'env_file': '.env.test',
        'extra': 'ignore',
    }


@pytest.fixture
def shield_settings() -> ShieldTestSettings:
    return ShieldTestSettings()  # type: ignore


class ValidatorTestSettings(ValidatorSettings):
    model_config = {
        'env_file': '.env.test',
        'extra': 'ignore',
    }


@pytest.fixture
def validator_settings() -> ValidatorTestSettings:
    return ValidatorTestSettings()  # type: ignore
