from __future__ import annotations

from bt_ddos_shield.utils import extract_commitment_url, merge_commitment_url, wrap_commitment_payload


def test_extract_commitment_with_envelope():
    url = 'https://example.com'
    commitment = wrap_commitment_payload(url)

    extracted_url, rest, is_legacy = extract_commitment_url(commitment)

    assert extracted_url == url
    assert rest == ''
    assert not is_legacy


def test_extract_commitment_with_other_segments():
    url = 'https://example.com'
    other = '<<CHM:payload>>'
    commitment = f'{other}{wrap_commitment_payload(url)}--tail'

    extracted_url, rest, is_legacy = extract_commitment_url(commitment)

    assert extracted_url == url
    assert rest == f'{other}--tail'
    assert not is_legacy


def test_extract_commitment_legacy_url():
    commitment = 'https://legacy-example.com'

    extracted_url, rest, is_legacy = extract_commitment_url(commitment)

    assert extracted_url == commitment
    assert rest == ''
    assert is_legacy


def test_extract_commitment_legacy_with_suffix():
    commitment = 'https://legacy-example.com<M:a=1>'

    extracted_url, rest, is_legacy = extract_commitment_url(commitment)

    assert extracted_url == 'https://legacy-example.com'
    assert rest == '<M:a=1>'
    assert is_legacy


def test_extract_commitment_without_shield_data():
    payload = '<<CHM:payload>>'

    extracted_url, rest, is_legacy = extract_commitment_url(payload)

    assert extracted_url is None
    assert rest == payload
    assert not is_legacy


def test_merge_commitment_preserves_other_segments():
    url = 'https://example.com'
    other = '<<CHM:payload>>'

    merged = merge_commitment_url(url, other)

    assert merged == f'{wrap_commitment_payload(url)}{other}'
