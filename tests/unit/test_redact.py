from __future__ import annotations

from pathlib import Path

from azazel_cti.security.redact import SecretRegistry, format_exception, redact_text


def test_redact_matches_token_regex():
    registry = SecretRegistry()
    text = "auth failed for azcti_key01_abcDEF123-_xyz on request"
    redacted = registry.redact(text)
    assert "azcti_key01_abcDEF123-_xyz" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_registered_value():
    registry = SecretRegistry()
    registry.register("s3kr1t-value")
    text = "the secret is s3kr1t-value in the payload"
    redacted = registry.redact(text)
    assert "s3kr1t-value" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_leaves_unrelated_text_untouched():
    registry = SecretRegistry()
    registry.register("s3kr1t-value")
    text = "nothing sensitive here"
    assert registry.redact(text) == text


def test_register_file_and_redact(tmp_path: Path):
    secret_file = tmp_path / "node_key"
    secret_file.write_text("top-secret-file-content")
    registry = SecretRegistry()
    registry.register_file(secret_file)
    redacted = registry.redact("payload contains top-secret-file-content here")
    assert "top-secret-file-content" not in redacted


def test_register_dir_and_redact(tmp_path: Path):
    (tmp_path / "a.key").write_text("secret-a")
    (tmp_path / "b.key").write_text("secret-b")
    registry = SecretRegistry()
    registry.register_dir(tmp_path)
    redacted = registry.redact("has secret-a and secret-b inside")
    assert "secret-a" not in redacted
    assert "secret-b" not in redacted


def test_redact_multiple_tokens_in_text():
    registry = SecretRegistry()
    text = "azcti_a_111 then azcti_b_222"
    redacted = registry.redact(text)
    assert "azcti_a_111" not in redacted
    assert "azcti_b_222" not in redacted


def test_format_exception_redacts_token_in_message():
    registry = SecretRegistry()
    try:
        raise ValueError("bad token azcti_key01_supersecret in request")
    except ValueError as exc:
        formatted = format_exception(exc, registry)
    assert "azcti_key01_supersecret" not in formatted
    assert "[REDACTED]" in formatted


def test_redact_text_without_registry_still_redacts_token_regex():
    text = "leaked azcti_key02_anothersecret here"
    redacted = redact_text(text)
    assert "azcti_key02_anothersecret" not in redacted


def test_register_dir_ignores_binary_files_and_redacts_text(tmp_path: Path):
    (tmp_path / "node_signing_key").write_bytes(b"\x90\x00binary-ed25519-key")
    (tmp_path / "api_token").write_text("text-secret", encoding="utf-8")

    registry = SecretRegistry()
    registry.register_dir(tmp_path)

    redacted = registry.redact("text-secret remains the only registered secret")
    assert redacted.count("[REDACTED]") == 1
    assert "text-secret" not in redacted
