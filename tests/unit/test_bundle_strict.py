from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_knowledge.bundle.importer import apply_differential, import_full
from azazel_knowledge.bundle.verify import (
    BundleVerifyError,
    _load_anchors,
    _safe_member,
    canonical_manifest_bytes,
    verify_bundle,
)
from azazel_knowledge.db import generations
from azazel_knowledge.db.repository import apply_migrations


@dataclass
class BundleCase:
    root: Path
    entrypoint: str
    signing_keys: dict[str, SigningKey]
    anchors: Path
    state: Path
    data: Path

    def write_anchors(
        self,
        threshold: str | None = "1",
        *,
        keys: tuple[str, ...] = ("one", "two"),
        revoked: tuple[str, ...] = (),
        roles: dict[str, str] | None = None,
        required_role: str | None = None,
    ) -> None:
        lines = [] if threshold is None else [f"threshold = {threshold}"]
        lines.append(f"revoked = {json.dumps(revoked)}")
        if required_role is not None:
            lines.append(f"required_signer_role = {json.dumps(required_role)}")
        lines.append("[keys]")
        lines.extend(
            f'{name} = "{self.signing_keys[name].verify_key.encode().hex()}"' for name in keys
        )
        lines.append("[key_roles]")
        lines.extend(f"{name} = {json.dumps(role)}" for name, role in (roles or {}).items())
        self.anchors.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def bundle(
        self,
        *,
        extra: dict[str, object] | None = None,
        members: dict[str, bytes] | None = None,
        declared_only: tuple[str, ...] = (),
        undeclared: dict[str, bytes] | None = None,
        signers: tuple[str, ...] = ("one",),
        initial: bool = False,
    ) -> Path:
        differential = self.entrypoint == "differential" and not initial
        prefix = "deltas" if differential else "tables"
        contents = {f"{prefix}/ioc.jsonl": b"", **(members or {})}
        manifest = {
            "bundle_version": 1 if initial else 2,
            "kind": "differential" if differential else "full",
            "base_version": 1 if differential else None,
            "compression": "gzip",
            "tables": ["ioc"],
            "files": {
                name: hashlib.sha256(payload).hexdigest() for name, payload in contents.items()
            },
        }
        manifest["files"].update({name: hashlib.sha256(b"").hexdigest() for name in declared_only})
        manifest.update(extra or {})
        raw = canonical_manifest_bytes(manifest)
        signatures = "".join(
            f"{name}:{self.signing_keys[name].sign(raw).signature.hex()}\n" for name in signers
        ).encode()
        path = self.root / ("initial.tar.gz" if initial else "candidate.tar.gz")
        with tarfile.open(path, "w:gz") as archive:
            for name, payload in (
                ("manifest.json", raw),
                ("manifest.sig", signatures),
                *contents.items(),
                *(undeclared or {}).items(),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        return path

    def run(self, bundle: Path) -> None:
        staging = self.root / "staging"
        if self.entrypoint == "verify":
            verify_bundle(bundle, self.anchors, self.state, staging)
        elif self.entrypoint == "full":
            import_full(bundle, self.anchors, self.state, self.data, staging_dir=staging)
        else:
            with sqlite3.connect(generations.intel_db_path(self.data, 1)) as connection:
                apply_differential(bundle, self.anchors, self.state, connection, staging_dir=staging)

    def assert_refused(self, bundle: Path, code: str) -> None:
        live = generations.intel_db_path(self.data, 1)
        before = hashlib.sha256(live.read_bytes()).digest()
        state_before = self.state.read_bytes()
        with pytest.raises(BundleVerifyError) as error:
            self.run(bundle)
        assert error.value.code == code
        assert generations.current_generation(self.data) == 1
        assert hashlib.sha256(live.read_bytes()).digest() == before
        assert self.state.read_bytes() == state_before
        assert sorted(path.name for path in self.data.glob("gen-*")) == ["gen-1"]
        assert not list((self.root / "staging").rglob("*"))


@pytest.fixture(params=("verify", "full", "differential"))
def case(tmp_path: Path, request: pytest.FixtureRequest) -> BundleCase:
    result = BundleCase(
        root=tmp_path,
        entrypoint=request.param,
        signing_keys={name: SigningKey.generate() for name in ("one", "two", "three")},
        anchors=tmp_path / "anchors.toml",
        state=tmp_path / "state.toml",
        data=tmp_path / "db",
    )
    result.write_anchors()
    import_full(result.bundle(initial=True), result.anchors, result.state, result.data)
    return result


@pytest.mark.parametrize("threshold", ("0", "-1", "true", "false", '"1"', "1.0", "1.5", "[1]"))
def test_threshold_requires_a_positive_non_boolean_integer(case: BundleCase, threshold: str) -> None:
    case.write_anchors(threshold)
    case.assert_refused(case.bundle(), "BUNDLE_ANCHORS_THRESHOLD_INVALID")
    with pytest.raises(BundleVerifyError) as error:
        _load_anchors(case.anchors)
    assert error.value.code == "BUNDLE_ANCHORS_THRESHOLD_INVALID"


def test_zero_threshold_cannot_admit_an_unsigned_bundle(case: BundleCase) -> None:
    case.write_anchors("0")
    case.assert_refused(case.bundle(signers=()), "BUNDLE_ANCHORS_THRESHOLD_INVALID")


@pytest.mark.parametrize(
    "threshold, keys, revoked, roles, required_role",
    (
        ("1", (), (), {}, None),
        ("3", ("one", "two"), (), {}, None),
        ("2", ("one", "two"), ("two",), {}, None),
        ("1", ("one",), ("one",), {}, None),
        ("1", ("one",), (), {}, "lite"),
        ("1", ("one",), (), {"one": "full"}, "lite"),
        ("1", ("one",), (), {"unknown": "lite"}, "lite"),
        ("1", ("one", "two"), ("two",), {"two": "lite"}, "lite"),
        ("2", ("one", "two"), (), {"one": "lite", "two": "full"}, "lite"),
    ),
)
def test_threshold_must_be_satisfiable_by_active_role_keys(
    case: BundleCase,
    threshold: str,
    keys: tuple[str, ...],
    revoked: tuple[str, ...],
    roles: dict[str, str],
    required_role: str | None,
) -> None:
    case.write_anchors(threshold, keys=keys, revoked=revoked, roles=roles, required_role=required_role)
    case.assert_refused(case.bundle(), "BUNDLE_ANCHORS_THRESHOLD_INVALID")
    with pytest.raises(BundleVerifyError) as error:
        _load_anchors(case.anchors)
    assert error.value.code == "BUNDLE_ANCHORS_THRESHOLD_INVALID"


@pytest.mark.parametrize("required_role", (None, "lite"))
def test_threshold_equal_to_eligible_key_count_is_accepted(
    case: BundleCase, required_role: str | None
) -> None:
    case.write_anchors(
        "2",
        keys=("one", "two", "three"),
        revoked=("three",),
        roles={"one": "lite", "two": "lite", "three": "lite"},
        required_role=required_role,
    )
    case.run(case.bundle(signers=("one", "two")))


def test_omitted_threshold_keeps_the_default_of_one(case: BundleCase) -> None:
    case.write_anchors(None)
    assert _load_anchors(case.anchors).threshold == 1
    case.run(case.bundle())


@pytest.mark.parametrize("version", (True, False, "2", 2.0, 2.5, None, [], {}, 0, -1))
def test_bundle_version_requires_a_positive_non_boolean_integer(
    case: BundleCase, version: object
) -> None:
    case.assert_refused(case.bundle(extra={"bundle_version": version}), "BUNDLE_VERSION_INVALID")


@pytest.mark.parametrize("name", ("a" * 256, "a" * 256 + "/x", "é" * 128))
@pytest.mark.parametrize("delivered", (True, False))
def test_overlong_component_is_refused_even_if_only_declared(
    case: BundleCase, name: str, delivered: bool
) -> None:
    assert len(name.encode("utf-8")) < 1024
    bundle = case.bundle(members={name: b""}) if delivered else case.bundle(declared_only=(name,))
    case.assert_refused(bundle, "BUNDLE_MEMBER_COMPONENT_TOO_LONG")
    with pytest.raises(BundleVerifyError) as error:
        _safe_member(tarfile.TarInfo(name))
    assert error.value.code == "BUNDLE_MEMBER_COMPONENT_TOO_LONG"


def test_undeclared_tar_member_also_has_a_component_limit(case: BundleCase) -> None:
    bundle = case.bundle(undeclared={"a" * 256: b""})
    with pytest.raises(BundleVerifyError) as error:
        case.run(bundle)
    assert error.value.code == "BUNDLE_MEMBER_COMPONENT_TOO_LONG"


@pytest.mark.parametrize("name", ("a" * 255, "a" * 255 + "/x", "界" * 85))
def test_component_at_255_utf8_bytes_is_accepted(case: BundleCase, name: str) -> None:
    assert max(len(part.encode("utf-8")) for part in name.split("/")) == 255
    assert _safe_member(tarfile.TarInfo(name)) == name
    case.run(case.bundle(members={name: b""}))


@pytest.mark.parametrize(
    "field, value",
    (
        ("key_roles", {"one": "lite"}),
        ("required_signer_role", "lite"),
        ("minimum_security_epoch", 0),
        ("accepted_export_policy_digests", ["allowed"]),
    ),
)
def test_manifest_cannot_embed_consumer_trust_policy(
    case: BundleCase, field: str, value: object
) -> None:
    case.assert_refused(case.bundle(extra={field: value}), "BUNDLE_SHADOWS_TRUST_ANCHOR")


def test_artifact_epoch_and_nested_export_policy_remain_valid(case: BundleCase) -> None:
    case.run(case.bundle(extra={
        "security_epoch": 3,
        "profile": {"selection_inputs": {"export_policy_digest": "recorded"}},
    }))


_REPO_ROOT = Path(__file__).resolve().parents[2]


def _azctl(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT / "src")}
    return subprocess.run(
        [sys.executable, str(_REPO_ROOT / "azctl"), *args],
        capture_output=True, text=True, env=env, check=False,
    )


def _resign_with_version(bundle: Path, key: SigningKey, version: int) -> None:
    """The builder now refuses such a version, so the manifest is edited and re-signed."""
    with tarfile.open(bundle, "r:gz") as archive:
        members = [(m.name, archive.extractfile(m).read()) for m in archive.getmembers()]
    manifest = json.loads(members[0][1])
    manifest["bundle_version"] = version
    raw = canonical_manifest_bytes(manifest)
    line = f"{key.verify_key.encode().hex()[:8]}:{key.sign(raw).signature.hex()}\n".encode()
    with tarfile.open(bundle, "w:gz") as archive:
        for name, payload in (("manifest.json", raw), ("manifest.sig", line), *members[2:]):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


@pytest.mark.parametrize(
    "threshold, version, code",
    (
        ("0", 1, "BUNDLE_ANCHORS_THRESHOLD_INVALID"),
        ("2", 1, "BUNDLE_ANCHORS_THRESHOLD_INVALID"),
        ("1", 0, "BUNDLE_VERSION_INVALID"),
    ),
)
def test_azctl_bundle_import_refuses_with_the_verifier_code(
    tmp_path: Path, threshold: str, version: int, code: str
) -> None:
    """The operator entry point refuses with the same code, before any generation is built."""
    root = tmp_path / "node"
    assert _azctl("provision", "--root", str(root)).returncode == 0
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as connection:
        connection.execute(
            "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
    with sqlite3.connect(source) as connection:
        apply_migrations(connection, "intel")
    key = SigningKey.generate()
    key_file = tmp_path / "key.hex"
    key_file.write_text(key.encode().hex() + "\n", encoding="utf-8")
    bundle = tmp_path / "bundle.tar.gz"
    built = _azctl(
        "bundle", "build", "--source-db", str(source), "--out", str(bundle),
        "--version", "1", "--sign-key", str(key_file),
    )
    assert built.returncode == 0, built.stderr
    if version != 1:
        _resign_with_version(bundle, key, version)
    verify_hex = key.verify_key.encode().hex()
    anchors = root / "secrets" / "trust" / "anchors.toml"
    anchors.write_text(
        f'threshold = {threshold}\nrevoked = []\n\n[keys]\n{verify_hex[:8]} = "{verify_hex}"\n',
        encoding="utf-8",
    )
    state = root / "secrets" / "trust" / "state.toml"
    state_before = state.read_bytes()
    gens_before = sorted(p.name for p in (root / "data" / "db").glob("gen-*"))

    result = _azctl("bundle", "import", "--root", str(root), str(bundle), "--confirm")

    assert result.returncode != 0
    assert code in result.stderr
    assert state.read_bytes() == state_before
    assert sorted(p.name for p in (root / "data" / "db").glob("gen-*")) == gens_before


@pytest.mark.parametrize("base", (True, False, "1", 1.0, 0, -1, [], {}))
def test_base_version_requires_null_or_a_positive_non_boolean_integer(
    case: BundleCase, base: object
) -> None:
    case.assert_refused(case.bundle(extra={"base_version": base}), "BUNDLE_BASE_VERSION_INVALID")


def test_null_base_is_a_mismatch_only_for_a_differential(case: BundleCase) -> None:
    bundle = case.bundle(extra={"base_version": None})
    if case.entrypoint == "differential":
        case.assert_refused(bundle, "BUNDLE_BASE_MISMATCH")
    else:
        case.run(bundle)


@pytest.mark.parametrize("flag, value", (("--version", "0"), ("--version", "-1"), ("--version", "x"),
                                          ("--base", "0"), ("--base", "true")))
def test_bundle_build_refuses_a_version_below_one(tmp_path: Path, flag: str, value: str) -> None:
    key_file = tmp_path / "key.hex"
    key_file.write_text(SigningKey.generate().encode().hex() + "\n", encoding="utf-8")
    out = tmp_path / "bundle.tar.gz"
    args = ["--version", "2", "--base", "1"]
    args[args.index(flag) + 1] = value
    for command in ("build", "build-lite"):
        if command == "build-lite" and flag == "--base":
            continue
        result = subprocess.run(
            [sys.executable, str(_REPO_ROOT / "tools" / "bundle_build.py"), command,
             "--source-db", str(tmp_path / "absent.db"), "--out", str(out),
             "--sign-key", str(key_file), *(args if command == "build" else args[:2])],
            capture_output=True, text=True, check=False,
            env={**os.environ, "PYTHONPATH": str(_REPO_ROOT / "src")},
        )
        assert result.returncode == 2, (command, result.stderr)
        assert flag in result.stderr
        assert not out.exists()


def _anchors_root(tmp_path: Path, body: str) -> tuple[Path, Path]:
    root = tmp_path / "node"
    assert _azctl("provision", "--root", str(root)).returncode == 0
    anchors = root / "secrets" / "trust" / "anchors.toml"
    anchors.write_text(body, encoding="utf-8")
    return root, anchors


def _hex() -> str:
    return SigningKey.generate().verify_key.encode().hex()


_TWO_KEYS = f'threshold = 1\nrevoked = []\n\n[keys]\nk1 = "{_hex()}"\nk2 = "{_hex()}"\n'
_ROLE_KEYS = (
    'threshold = 1\nrevoked = []\nrequired_signer_role = "lite"\nminimum_security_epoch = 3\n'
    'accepted_export_policy_digests = ["p1"]\n\n'
    f'[keys]\nk1 = "{_hex()}"\nk2 = "{_hex()}"\n\n[key_roles]\nk1 = "lite"\nk2 = "full"\n'
)


@pytest.mark.parametrize(
    "body, command",
    (
        (_TWO_KEYS, ("keys", "set-threshold", "0")),
        (_TWO_KEYS, ("keys", "set-threshold", "-1")),
        (_TWO_KEYS, ("keys", "set-threshold", "3")),
        (_ROLE_KEYS, ("keys", "set-threshold", "2")),
        (_ROLE_KEYS, ("keys", "remove", "k1")),
        (_ROLE_KEYS, ("keys", "remove", "k1", "--revoke")),
        (f'threshold = 2\nrevoked = []\n\n[keys]\nk1 = "{_hex()}"\nk2 = "{_hex()}"\n',
         ("keys", "remove", "k2", "--revoke")),
        (f'threshold = 1.5\nrevoked = []\n\n[keys]\nk1 = "{_hex()}"\n', ("keys", "add", "k2", _hex())),
    ),
)
def test_azctl_keys_refuses_to_write_an_unsatisfiable_anchor(
    tmp_path: Path, body: str, command: tuple[str, ...]
) -> None:
    root, anchors = _anchors_root(tmp_path, body)
    result = _azctl(*command[:2], "--root", str(root), *command[2:])
    assert result.returncode != 0
    assert "BUNDLE_ANCHORS_THRESHOLD_INVALID" in result.stderr
    assert anchors.read_text(encoding="utf-8") == body


def test_azctl_keys_keeps_the_consumer_policy_across_a_rewrite(tmp_path: Path) -> None:
    root, anchors = _anchors_root(tmp_path, _ROLE_KEYS)
    before = tomllib.loads(_ROLE_KEYS)
    new_hex = _hex()
    assert _azctl("keys", "add", "--root", str(root), "k3", new_hex).returncode == 0
    assert _azctl("keys", "remove", "--root", str(root), "k2", "--revoke").returncode == 0
    after = tomllib.loads(anchors.read_text(encoding="utf-8"))
    for name in ("required_signer_role", "minimum_security_epoch",
                 "accepted_export_policy_digests", "key_roles"):
        assert after[name] == before[name]
    assert after["keys"] == {"k1": before["keys"]["k1"], "k3": new_hex}
    assert after["revoked"] == ["k2"]
    assert _load_anchors(anchors).required_signer_role == "lite"
