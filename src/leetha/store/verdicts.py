"""Verdict repository -- computed host assessments."""
from __future__ import annotations

import json
from datetime import datetime
from leetha.evidence.models import Evidence, Verdict


class VerdictRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS verdicts (
                hw_addr TEXT PRIMARY KEY,
                category TEXT,
                vendor TEXT,
                platform TEXT,
                platform_version TEXT,
                model TEXT,
                hostname TEXT,
                certainty INTEGER DEFAULT 0,
                evidence_chain TEXT DEFAULT '[]',
                computed_at TEXT NOT NULL
            )
        """)
        await self._conn.commit()

    async def upsert(self, verdict: Verdict) -> None:
        chain_json = json.dumps([e.to_dict() for e in verdict.evidence_chain])
        await self._conn.execute("""
            INSERT INTO verdicts (hw_addr, category, vendor, platform,
                                  platform_version, model, hostname,
                                  certainty, evidence_chain, computed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hw_addr) DO UPDATE SET
                category = excluded.category,
                vendor = excluded.vendor,
                platform = excluded.platform,
                platform_version = excluded.platform_version,
                model = excluded.model,
                hostname = COALESCE(excluded.hostname, verdicts.hostname),
                certainty = excluded.certainty,
                evidence_chain = excluded.evidence_chain,
                computed_at = excluded.computed_at
        """, (verdict.hw_addr, verdict.category, verdict.vendor,
              verdict.platform, verdict.platform_version, verdict.model,
              verdict.hostname, verdict.certainty, chain_json,
              verdict.computed_at.isoformat()))
        await self._conn.commit()

    async def find_by_addr(self, hw_addr: str) -> Verdict | None:
        cursor = await self._conn.execute(
            "SELECT * FROM verdicts WHERE hw_addr = ?", (hw_addr,))
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_verdict(row)

    async def find_all(self, limit: int = 500) -> list[Verdict]:
        cursor = await self._conn.execute(
            "SELECT * FROM verdicts ORDER BY certainty DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_verdict(r) for r in rows]

    def _row_to_verdict(self, row) -> Verdict:
        chain_data = json.loads(row["evidence_chain"]) if row["evidence_chain"] else []
        evidence_chain = []
        for e in chain_data:
            evidence_chain.append(Evidence(
                source=e.get("source", ""),
                method=e.get("method", ""),
                certainty=e.get("certainty", 0.0),
                category=e.get("category"),
                vendor=e.get("vendor"),
                platform=e.get("platform"),
                platform_version=e.get("platform_version"),
                model=e.get("model"),
                hostname=e.get("hostname"),
                raw=e.get("raw", {}),
            ))
        return Verdict(
            hw_addr=row["hw_addr"],
            category=row["category"],
            vendor=row["vendor"],
            platform=row["platform"],
            platform_version=row["platform_version"],
            model=row["model"],
            hostname=row["hostname"],
            certainty=row["certainty"],
            evidence_chain=evidence_chain,
            computed_at=datetime.fromisoformat(row["computed_at"]),
        )
