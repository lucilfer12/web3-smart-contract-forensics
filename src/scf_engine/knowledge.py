from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import AnalysisResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  pragma TEXT,
  UNIQUE(file, sha256)
);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  name TEXT,
  file TEXT,
  line INTEGER,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS relationships (
  source_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT,
  PRIMARY KEY(source_id, target_id, kind)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  contract TEXT,
  function TEXT,
  file TEXT,
  line INTEGER,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class KnowledgeStore:
    def __init__(self, path: str = ".scf/scf.db") -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def ingest(self, result: AnalysisResult) -> None:
        with self.conn:
            for unit in result.sources:
                self.conn.execute(
                    "INSERT OR IGNORE INTO sources(file, sha256, pragma) VALUES (?, ?, ?)",
                    (unit.file, unit.source_hash, unit.pragma),
                )
                for contract in unit.contracts.values():
                    cid = f"contract:{unit.file}:{contract.name}"
                    self._entity(cid, "contract", contract.name, contract.location.file, contract.location.line, contract.__dict__)
                    for var in contract.state_variables.values():
                        vid = f"state:{unit.file}:{contract.name}:{var.name}"
                        self._entity(vid, "state", var.name, var.location.file, var.location.line, var.__dict__)
                        self._relation(cid, vid, "contains", None)
                    for function in contract.functions.values():
                        fid = f"function:{unit.file}:{contract.name}:{function.signature}"
                        self._entity(fid, "function", function.signature, function.location.file, function.location.line, function.__dict__)
                        self._relation(cid, fid, "contains", None)
            for edge in result.graph.get("edges", []):
                self._relation(str(edge.get("from")), str(edge.get("to")), str(edge.get("type", "related")), edge)
            for finding in result.findings:
                location = finding.evidence[0].source if finding.evidence else None
                self.conn.execute(
                    "INSERT INTO findings(rule_id,severity,confidence,contract,function,file,line,payload) VALUES (?,?,?,?,?,?,?,?)",
                    (finding.rule_id, finding.severity, finding.confidence, finding.contract, finding.function,
                     location.file if location else None, location.line if location else None, json.dumps(finding.__dict__, default=_json_default)),
                )

    def _entity(self, entity_id: str, kind: str, name: str, file: str, line: int, payload: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO entities(id,type,name,file,line,payload) VALUES (?,?,?,?,?,?)",
            (entity_id, kind, name, file, line, json.dumps(payload, default=_json_default)),
        )

    def _relation(self, source_id: str, target_id: str, kind: str, payload: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO relationships(source_id,target_id,kind,payload) VALUES (?,?,?,?)",
            (source_id, target_id, kind, json.dumps(payload, default=_json_default) if payload is not None else None),
        )

    def findings(self, rule_id: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if rule_id:
            clauses.append("rule_id = ?"); params.append(rule_id)
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.conn.execute("SELECT * FROM findings" + where + " ORDER BY confidence DESC, id DESC", params).fetchall()
        return [dict(row) | {"payload": json.loads(row["payload"])} for row in rows]

    def graph(self) -> dict[str, list[dict[str, Any]]]:
        nodes = [dict(row) for row in self.conn.execute("SELECT id,type,name,file,line,payload FROM entities").fetchall()]
        for node in nodes:
            node["payload"] = json.loads(node["payload"])
        edges = [dict(row) for row in self.conn.execute("SELECT source_id AS \"from\", target_id AS \"to\", kind AS type, payload FROM relationships").fetchall()]
        for edge in edges:
            edge["payload"] = json.loads(edge["payload"]) if edge["payload"] else None
        return {"nodes": nodes, "edges": edges}

    def stats(self) -> dict[str, int]:
        return {
            "sources": self.conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            "entities": self.conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            "relationships": self.conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0],
            "findings": self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
        }


def _json_default(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {name: getattr(value, name) for name in value.__dataclass_fields__}
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(type(value).__name__)
