from __future__ import annotations

import pytest

from azazel_grimoire.security.auth import (
    Forbidden,
    InvalidToken,
    Scope,
    hash_secret,
    mint_token,
    parse_token,
    require_scope,
    verify,
)


def test_parse_token_roundtrip():
    key_id, secret = parse_token("azcti_key01_supersecretvalue")
    assert key_id == "key01"
    assert secret == "supersecretvalue"


def test_parse_token_secret_may_contain_underscores():
    key_id, secret = parse_token("azcti_key01_part1_part2_part3")
    assert key_id == "key01"
    assert secret == "part1_part2_part3"


def test_parse_token_rejects_bad_prefix():
    with pytest.raises(InvalidToken):
        parse_token("nottoken_key01_secret")


def test_parse_token_rejects_missing_parts():
    with pytest.raises(InvalidToken):
        parse_token("azcti_onlykey")


def test_hash_secret_is_sha256_hex():
    digest = hash_secret("abc")
    assert len(digest) == 64
    assert digest == hash_secret("abc")
    assert digest != hash_secret("abd")


def test_mint_token_verifies():
    token, stored_hash = mint_token("edge01")
    assert token.startswith("azcti_edge01_")
    assert verify(token, stored_hash)


def test_mint_token_generates_unique_secrets():
    token1, _ = mint_token("edge01")
    token2, _ = mint_token("edge01")
    assert token1 != token2


def test_verify_rejects_wrong_secret():
    token, stored_hash = mint_token("edge01")
    tampered = token[:-1] + ("a" if token[-1] != "a" else "b")
    assert not verify(tampered, stored_hash)


def test_verify_rejects_malformed_token():
    assert not verify("not-a-token", hash_secret("x"))


def test_require_scope_allows_present_scope():
    require_scope({Scope.INGEST, Scope.QUERY}, Scope.INGEST)


def test_require_scope_denies_by_default():
    with pytest.raises(Forbidden):
        require_scope({Scope.INGEST, Scope.QUERY}, Scope.ADMIN)


def test_require_scope_denies_empty_scopes():
    with pytest.raises(Forbidden):
        require_scope(set(), Scope.READ)


def test_edge_scope_never_admin():
    edge_scopes = {Scope.INGEST, Scope.QUERY}
    with pytest.raises(Forbidden):
        require_scope(edge_scopes, Scope.ADMIN)
