from __future__ import annotations

import json

import yaml

from azazel_cti.rules.lint import lint_sigma, lint_suricata, parse_suricata
from azazel_cti.rules.sigma import build_sigma
from azazel_cti.rules.suricata import (
    SuricataSlots,
    allocate_sid,
    build_suricata,
    escape_content,
    unescape_content,
)

GENERATED_AT = "2026-07-06T12:00:00Z"
PROVENANCE = {"ioc_ids": [1, 2], "feed_ids": ["urlhaus"], "generated_at": GENERATED_AT}


def _slots(**overrides) -> SuricataSlots:
    base = dict(
        proto="http",
        src="any",
        sport="any",
        direction="->",
        dst="$HOME_NET",
        dport="80",
        msg="AZAZEL advisory draft",
        contents=("evil-payload",),
    )
    base.update(overrides)
    return SuricataSlots(**base)


def _build(slots: SuricataSlots, counter: int = 1):
    return build_suricata(
        slots,
        sid_base=9000000,
        counter=counter,
        provenance=PROVENANCE,
        confidence=68.0,
        generated_at=GENERATED_AT,
    )


def test_basic_suricata_draft_and_lint_round_trip():
    draft = _build(_slots())
    assert draft is not None
    assert draft.format == "suricata"
    assert draft.content.startswith("alert http any any -> $HOME_NET 80 (")
    assert 'content:"evil-payload";' in draft.content
    assert lint_suricata(draft.content) is True


def test_sid_allocation_from_base_and_counter():
    assert allocate_sid(9000000, 5) == "9000005"
    a = _build(_slots(), counter=1)
    b = _build(_slots(), counter=2)
    assert a.sid == "9000001"
    assert b.sid == "9000002"
    assert a.sid != b.sid


def test_hostile_ioc_value_is_escaped_and_round_trips():
    hostile = '";alert tcp any any -> any any (msg:"pwned";);\\x00\n\x01|00|'
    draft = _build(_slots(contents=(hostile,)))
    assert draft is not None
    # raw metacharacters must not appear unescaped in the content option
    parsed = parse_suricata(draft.content)
    content_values = [v for k, v in parsed["options"] if k == "content"]
    assert len(content_values) == 1
    inner = content_values[0][1:-1]
    assert unescape_content(inner) == hostile
    # the rule still parses as exactly one rule with our sid
    sids = [v for k, v in parsed["options"] if k == "sid"]
    assert sids == [draft.sid]
    assert lint_suricata(draft.content) is True


def test_escape_content_escapes_metacharacters_and_nonprintables():
    assert escape_content('a"b') == 'a\\"b'
    assert escape_content("a;b") == "a\\;b"
    assert escape_content("a\\b") == "a\\\\b"
    assert escape_content("a|b") == "a|7C|b"
    assert escape_content("a\nb") == "a|0A|b"
    assert escape_content("a\x00b") == "a|00|b"
    assert escape_content("café") == "caf|E9|"


def test_unescape_inverts_escape():
    for raw in ('";)', "a;b\\c|d", "\x00\x01\xff", "plain", 'msg:"x";'):
        assert unescape_content(escape_content(raw)) == raw


def test_grammar_failure_returns_none():
    assert _build(_slots(proto="quic")) is None
    assert _build(_slots(direction="<-")) is None
    assert _build(_slots(src='1.2.3.4"; drop')) is None
    assert _build(_slots(dport="80; alert")) is None
    assert _build(_slots(msg="   ")) is None


def test_provenance_attached_to_suricata_draft():
    draft = _build(_slots())
    assert draft.provenance["ioc_ids"] == [1, 2]
    assert draft.provenance["feed_ids"] == ["urlhaus"]
    assert draft.provenance["generated_at"] == GENERATED_AT
    assert draft.provenance["confidence"] == 68.0
    parsed = parse_suricata(draft.content)
    metadata = next(v for k, v in parsed["options"] if k == "metadata")
    prefix, hexpart = metadata.split(" ", 1)
    assert prefix == "azazel_provenance"
    assert json.loads(bytes.fromhex(hexpart)) == draft.provenance


def test_lint_rejects_tampered_rule():
    draft = _build(_slots())
    tampered = draft.content.replace("(", "(  ", 1)
    assert lint_suricata(tampered) is False
    assert lint_suricata("not a rule at all") is False


def test_sigma_draft_and_lint():
    draft = build_sigma(
        title="AZAZEL advisory sigma draft",
        logsource={"category": "proxy"},
        selection={"cs-host": "evil.example.com"},
        sid_base=9100000,
        counter=3,
        provenance=PROVENANCE,
        confidence=61.0,
        generated_at=GENERATED_AT,
    )
    assert draft is not None
    assert draft.format == "sigma"
    assert draft.sid == "9100003"
    assert lint_sigma(draft.content) is True
    loaded = yaml.safe_load(draft.content)
    assert loaded["detection"]["selection"] == {"cs-host": "evil.example.com"}
    assert loaded["azazel_provenance"]["feed_ids"] == ["urlhaus"]
    assert loaded["azazel_provenance"]["confidence"] == 61.0


def test_sigma_hostile_values_are_safely_dumped():
    hostile = "evil\n- injected: true\n\"'; DROP"
    draft = build_sigma(
        title="hostile",
        logsource={"category": "dns"},
        selection={"query": hostile},
        sid_base=9100000,
        counter=4,
        generated_at=GENERATED_AT,
    )
    assert draft is not None
    loaded = yaml.safe_load(draft.content)
    assert loaded["detection"]["selection"]["query"] == hostile
    assert "injected" not in loaded
    assert lint_sigma(draft.content) is True


def test_sigma_grammar_failures_return_none():
    assert (
        build_sigma(
            title="  ",
            logsource={"category": "dns"},
            selection={"a": 1},
            sid_base=1,
            counter=1,
            generated_at=GENERATED_AT,
        )
        is None
    )
    assert (
        build_sigma(
            title="x",
            logsource={"category": "dns"},
            selection={},
            sid_base=1,
            counter=1,
            generated_at=GENERATED_AT,
        )
        is None
    )
    assert (
        build_sigma(
            title="x",
            logsource={},
            selection={"a": 1},
            sid_base=1,
            counter=1,
            generated_at=GENERATED_AT,
        )
        is None
    )


def test_no_deploy_channel_in_rules_modules():
    import inspect

    from azazel_cti.rules import lint, sigma, suricata

    for module in (suricata, sigma, lint):
        source = inspect.getsource(module)
        for forbidden in ("subprocess", "socket", "requests", "urllib", "deploy"):
            assert forbidden not in source, (module.__name__, forbidden)
