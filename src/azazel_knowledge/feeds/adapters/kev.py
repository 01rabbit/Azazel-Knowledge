"""CISA Known Exploited Vulnerabilities catalog feed adapter (design S6, F-14).

Full-replace: `kev` is deleted and repopulated in one writer transaction,
carrying `catalogVersion`/`dateReleased` from the source document. KEV
never appears in `ioc`/`ioc_source` or a lookup's `sources[]` -- it only
scores through the `cve_exploited` component.
"""

from __future__ import annotations

import json
from typing import Any

from azazel_knowledge.feeds.base import FeedAdapter, FeedError

_CVE_ID_MAX_LEN = 32
_TEXT_MAX_LEN = 4096


class KevAdapter(FeedAdapter):
    full_replace = True

    def parse(self, raw: bytes) -> list[dict[str, Any]]:
        document = json.loads(raw)
        catalog_version = document.get("catalogVersion")
        if not catalog_version:
            raise FeedError("cisa_kev: missing catalogVersion")
        vulnerabilities = document.get("vulnerabilities", [])
        rows: list[dict[str, Any]] = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            date_added = vuln.get("dateAdded")
            if not cve_id or not date_added:
                continue
            rows.append(
                {
                    "cve_id": cve_id,
                    "catalog_version": catalog_version,
                    "date_added": date_added,
                    "due_date": vuln.get("dueDate"),
                    "vendor_project": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "short_description": vuln.get("shortDescription"),
                    "required_action": vuln.get("requiredAction"),
                }
            )
        return rows

    def validate(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        valid: list[dict[str, Any]] = []
        for row in items:
            if len(row["cve_id"]) > _CVE_ID_MAX_LEN:
                continue
            if any(isinstance(v, str) and len(v) > _TEXT_MAX_LEN for v in row.values()):
                continue
            valid.append(row)
        return valid

    def apply_batch(self, batch: list[dict[str, Any]]) -> int:
        def txn(conn: Any) -> int:
            conn.execute("DELETE FROM kev")
            conn.executemany(
                "INSERT INTO kev (cve_id, catalog_version, date_added, due_date, vendor_project, "
                "product, vulnerability_name, short_description, required_action) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        row["cve_id"],
                        row["catalog_version"],
                        row["date_added"],
                        row.get("due_date"),
                        row.get("vendor_project"),
                        row.get("product"),
                        row.get("vulnerability_name"),
                        row.get("short_description"),
                        row.get("required_action"),
                    )
                    for row in batch
                ],
            )
            return len(batch)

        return self._exec_intel(txn)
