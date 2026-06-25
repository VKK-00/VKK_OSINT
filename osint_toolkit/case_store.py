from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from .investigation import InvestigationResult

SCHEMA_VERSION = "3"


class CaseStoreError(Exception):
    pass


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    title: str
    generated_at: str
    saved_at: str
    target_count: int
    entity_count: int
    finding_count: int
    edge_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "generated_at": self.generated_at,
            "saved_at": self.saved_at,
            "target_count": self.target_count,
            "entity_count": self.entity_count,
            "finding_count": self.finding_count,
            "edge_count": self.edge_count,
        }


@dataclass(frozen=True)
class CaseEntityRecord:
    kind: str
    value: str
    case_count: int
    cases: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "case_count": self.case_count,
            "cases": list(self.cases),
        }


@dataclass(frozen=True)
class CaseEntityHit:
    case_id: str
    title: str
    saved_at: str
    kind: str
    value: str
    source: str
    confidence: str
    note: str

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "saved_at": self.saved_at,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "note": self.note,
        }


class CaseStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def save(
        self,
        result: InvestigationResult,
        *,
        case_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> str:
        normalized_case_id = (case_id or uuid.uuid4().hex).strip()
        if not normalized_case_id:
            raise CaseStoreError("case_id cannot be empty.")

        saved_at = datetime.now().astimezone().isoformat(timespec="seconds")
        with self._open() as conn:
            _ensure_schema(conn)
            conn.execute("DELETE FROM cases WHERE case_id = ?", (normalized_case_id,))
            conn.execute(
                """
                INSERT INTO cases(case_id, title, generated_at, saved_at)
                VALUES (?, ?, ?, ?)
                """,
                (normalized_case_id, result.title, result.generated_at, saved_at),
            )
            conn.executemany(
                """
                INSERT INTO targets(case_id, ordinal, kind, value, region)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (normalized_case_id, ordinal, target.kind, target.value, target.region)
                    for ordinal, target in enumerate(result.targets)
                ),
            )
            conn.executemany(
                """
                INSERT INTO entities(case_id, ordinal, kind, value, source, confidence, note)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        normalized_case_id,
                        ordinal,
                        entity.kind,
                        entity.value,
                        entity.source,
                        entity.confidence,
                        entity.note,
                    )
                    for ordinal, entity in enumerate(result.entities)
                ),
            )
            finding_rows = []
            for collection, findings in (
                ("native", result.findings),
                ("adapter", result.adapter_findings),
            ):
                for ordinal, finding in enumerate(findings):
                    finding_rows.append(
                        (
                            normalized_case_id,
                            collection,
                            ordinal,
                            finding.module,
                            finding.source,
                            finding.target,
                            finding.status,
                            finding.url,
                            finding.title,
                            finding.http_status,
                            finding.confidence,
                            finding.evidence,
                            json.dumps(finding.metadata, ensure_ascii=False, sort_keys=True),
                            finding.checked_at,
                        )
                    )
            conn.executemany(
                """
                INSERT INTO findings(
                    case_id, collection, ordinal, module, source, target, status,
                    url, title, http_status, confidence, evidence, metadata_json, checked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                finding_rows,
            )
            conn.executemany(
                """
                INSERT INTO edges(
                    case_id, ordinal, source_kind, source_value, relation,
                    target_kind, target_value, source, confidence, note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        normalized_case_id,
                        ordinal,
                        edge.source_kind,
                        edge.source_value,
                        edge.relation,
                        edge.target_kind,
                        edge.target_value,
                        edge.source,
                        edge.confidence,
                        edge.note,
                    )
                    for ordinal, edge in enumerate(result.edges)
                ),
            )
            if metadata:
                conn.executemany(
                    """
                    INSERT INTO case_metadata(case_id, key, value_json)
                    VALUES (?, ?, ?)
                    """,
                    (
                        (
                            normalized_case_id,
                            key,
                            json.dumps(value, ensure_ascii=False, sort_keys=True),
                        )
                        for key, value in sorted(metadata.items())
                    ),
                )
        return normalized_case_id

    def list_cases(self, *, limit: int = 20) -> tuple[CaseRecord, ...]:
        if limit < 1:
            raise CaseStoreError("limit must be greater than zero.")
        with self._open() as conn:
            _ensure_schema(conn)
            rows = conn.execute(
                """
                SELECT
                    cases.case_id,
                    cases.title,
                    cases.generated_at,
                    cases.saved_at,
                    (SELECT COUNT(*) FROM targets WHERE targets.case_id = cases.case_id) AS target_count,
                    (SELECT COUNT(*) FROM entities WHERE entities.case_id = cases.case_id) AS entity_count,
                    (SELECT COUNT(*) FROM findings WHERE findings.case_id = cases.case_id) AS finding_count,
                    (SELECT COUNT(*) FROM edges WHERE edges.case_id = cases.case_id) AS edge_count
                FROM cases
                ORDER BY cases.saved_at DESC, cases.case_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(
            CaseRecord(
                case_id=row["case_id"],
                title=row["title"],
                generated_at=row["generated_at"],
                saved_at=row["saved_at"],
                target_count=row["target_count"],
                entity_count=row["entity_count"],
                finding_count=row["finding_count"],
                edge_count=row["edge_count"],
            )
            for row in rows
        )

    def load_case(self, case_id: str) -> dict[str, object]:
        with self._open() as conn:
            _ensure_schema(conn)
            case = conn.execute(
                "SELECT case_id, title, generated_at, saved_at FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise CaseStoreError(f"case not found: {case_id}")
            targets = conn.execute(
                """
                SELECT kind, value, region
                FROM targets
                WHERE case_id = ?
                ORDER BY ordinal
                """,
                (case_id,),
            ).fetchall()
            entities = conn.execute(
                """
                SELECT kind, value, source, confidence, note
                FROM entities
                WHERE case_id = ?
                ORDER BY ordinal
                """,
                (case_id,),
            ).fetchall()
            findings = conn.execute(
                """
                SELECT collection, module, source, target, status, url, title, http_status,
                       confidence, evidence, metadata_json, checked_at
                FROM findings
                WHERE case_id = ?
                ORDER BY CASE collection WHEN 'native' THEN 0 ELSE 1 END, ordinal
                """,
                (case_id,),
            ).fetchall()
            edges = conn.execute(
                """
                SELECT source_kind, source_value, relation, target_kind, target_value, source, confidence, note
                FROM edges
                WHERE case_id = ?
                ORDER BY ordinal
                """,
                (case_id,),
            ).fetchall()
            metadata_rows = conn.execute(
                """
                SELECT key, value_json
                FROM case_metadata
                WHERE case_id = ?
                ORDER BY key
                """,
                (case_id,),
            ).fetchall()
        return {
            "case": dict(case),
            "targets": [dict(row) for row in targets],
            "entities": [dict(row) for row in entities],
            "edges": [dict(row) for row in edges],
            "findings": [_finding_row_to_dict(row) for row in findings],
            "metadata": {
                row["key"]: json.loads(row["value_json"] or "null")
                for row in metadata_rows
            },
        }

    def load_cases(self, *, limit: int = 100) -> tuple[dict[str, object], ...]:
        if limit < 1:
            raise CaseStoreError("limit must be greater than zero.")
        records = self.list_cases(limit=limit)
        return tuple(self.load_case(record.case_id) for record in records)

    def list_entity_index(
        self,
        *,
        kind: str = "",
        min_cases: int = 1,
        limit: int = 50,
    ) -> tuple[CaseEntityRecord, ...]:
        normalized_kind = kind.strip()
        if min_cases < 1:
            raise CaseStoreError("min_cases must be greater than zero.")
        if limit < 1:
            raise CaseStoreError("limit must be greater than zero.")

        where = ""
        params: list[object] = []
        if normalized_kind:
            where = "WHERE lower(kind) = lower(?)"
            params.append(normalized_kind)

        with self._open() as conn:
            _ensure_schema(conn)
            rows = conn.execute(
                f"""
                SELECT kind, value, COUNT(DISTINCT case_id) AS case_count
                FROM entities
                {where}
                GROUP BY kind, lower(value)
                HAVING case_count >= ?
                ORDER BY case_count DESC, kind ASC, lower(value) ASC
                LIMIT ?
                """,
                (*params, min_cases, limit),
            ).fetchall()

            records: list[CaseEntityRecord] = []
            for row in rows:
                cases = conn.execute(
                    """
                    SELECT DISTINCT cases.case_id, cases.saved_at
                    FROM entities
                    JOIN cases ON cases.case_id = entities.case_id
                    WHERE lower(entities.kind) = lower(?)
                      AND lower(entities.value) = lower(?)
                    ORDER BY cases.saved_at DESC, cases.case_id DESC
                    """,
                    (row["kind"], row["value"]),
                ).fetchall()
                records.append(
                    CaseEntityRecord(
                        kind=row["kind"],
                        value=row["value"],
                        case_count=row["case_count"],
                        cases=tuple(case["case_id"] for case in cases),
                    )
                )
        return tuple(records)

    def find_cases_by_entity(self, *, kind: str, value: str) -> tuple[CaseEntityHit, ...]:
        normalized_kind = kind.strip()
        normalized_value = value.strip()
        if not normalized_kind:
            raise CaseStoreError("kind cannot be empty.")
        if not normalized_value:
            raise CaseStoreError("value cannot be empty.")

        with self._open() as conn:
            _ensure_schema(conn)
            rows = conn.execute(
                """
                SELECT
                    cases.case_id,
                    cases.title,
                    cases.saved_at,
                    entities.kind,
                    entities.value,
                    entities.source,
                    entities.confidence,
                    entities.note
                FROM entities
                JOIN cases ON cases.case_id = entities.case_id
                WHERE lower(entities.kind) = lower(?)
                  AND lower(entities.value) = lower(?)
                ORDER BY cases.saved_at DESC, cases.case_id DESC
                """,
                (normalized_kind, normalized_value),
            ).fetchall()
        return tuple(
            CaseEntityHit(
                case_id=row["case_id"],
                title=row["title"],
                saved_at=row["saved_at"],
                kind=row["kind"],
                value=row["value"],
                source=row["source"],
                confidence=row["confidence"],
                note=row["note"],
            )
            for row in rows
        )

    @contextmanager
    def _open(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            saved_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS targets (
            case_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            region TEXT NOT NULL,
            PRIMARY KEY (case_id, ordinal),
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS entities (
            case_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            note TEXT NOT NULL,
            PRIMARY KEY (case_id, ordinal),
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            case_id TEXT NOT NULL,
            collection TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            module TEXT NOT NULL,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            url TEXT NOT NULL,
            title TEXT NOT NULL,
            http_status INTEGER,
            confidence TEXT NOT NULL,
            evidence TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            PRIMARY KEY (case_id, collection, ordinal),
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS edges (
            case_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            source_kind TEXT NOT NULL,
            source_value TEXT NOT NULL,
            relation TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            target_value TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            note TEXT NOT NULL,
            PRIMARY KEY (case_id, ordinal),
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS case_metadata (
            case_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            PRIMARY KEY (case_id, key),
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", SCHEMA_VERSION),
    )


def _finding_row_to_dict(row: sqlite3.Row) -> dict[str, object]:
    value = dict(row)
    value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
    return value
