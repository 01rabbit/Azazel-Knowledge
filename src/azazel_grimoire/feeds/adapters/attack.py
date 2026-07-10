"""MITRE ATT&CK enterprise STIX 2.1 feed adapter (design S6).

Full-replace: `attack_technique`/`attack_mitigation`/`attack_relation`
are deleted and repopulated in a single writer transaction, pinned to
`attack_version` resolved by `attack.attack_stix.flatten`. ATT&CK never
touches `ioc`/`ioc_source`.
"""

from __future__ import annotations

import json
from typing import Any

from azazel_grimoire.attack.attack_stix import FlattenedAttack, flatten
from azazel_grimoire.feeds.base import FeedAdapter


class AttackAdapter(FeedAdapter):
    full_replace = True

    def parse(self, raw: bytes) -> FlattenedAttack:
        bundle = json.loads(raw)
        version_override = self.config.get("attack_version")
        return flatten(bundle, version_override=version_override)

    def item_count(self, items: FlattenedAttack) -> int:
        return len(items)

    def apply_batch(self, batch: FlattenedAttack) -> int:
        def txn(conn: Any) -> int:
            conn.execute("DELETE FROM attack_relation")
            conn.execute("DELETE FROM attack_mitigation")
            conn.execute("DELETE FROM attack_technique")
            conn.executemany(
                "INSERT INTO attack_technique (technique_id, name, tactics, is_subtechnique, "
                "parent_technique_id, description, data_sources, platforms, attack_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        t.technique_id,
                        t.name,
                        json.dumps(t.tactics),
                        int(t.is_subtechnique),
                        t.parent_technique_id,
                        t.description,
                        json.dumps(t.data_sources),
                        json.dumps(t.platforms),
                        batch.attack_version,
                    )
                    for t in batch.techniques
                ],
            )
            conn.executemany(
                "INSERT INTO attack_mitigation (mitigation_id, name, description, attack_version) "
                "VALUES (?, ?, ?, ?)",
                [(m.mitigation_id, m.name, m.description, batch.attack_version) for m in batch.mitigations],
            )
            conn.executemany(
                "INSERT INTO attack_relation (source_id, source_type, relation_type, target_id, "
                "target_type, attack_version) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (r.source_id, r.source_type, r.relation_type, r.target_id, r.target_type, batch.attack_version)
                    for r in batch.relations
                ],
            )
            return len(batch)

        return self._exec_intel(txn)
