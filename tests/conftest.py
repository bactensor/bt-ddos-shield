import pytest

from bt_ddos_shield.miner_shield import ShieldSettings
from bt_ddos_shield.validator import ValidatorSettings


class ShieldTestSettings(ShieldSettings):
    aws_route53_other_hosted_zone_id: str
    miner_instance_port: int = 8080

    model_config = {
        'env_file': '.env.test',
        'extra': 'ignore',
    }


@pytest.fixture
def shield_settings() -> ShieldTestSettings:
    settings: ShieldTestSettings = ShieldTestSettings()  # type: ignore
    settings.options.retry_limit = 1  # Do not retry forever as tests can hang
    return settings


class ValidatorTestSettings(ValidatorSettings):
    validator_public_key: str
    miner_instance_port: int = 8080

    model_config = {
        'env_file': '.env.test',
        'extra': 'ignore',
    }


@pytest.fixture
def validator_settings() -> ValidatorTestSettings:
    return ValidatorTestSettings()  # type: ignore
