"""Campaign memory (SQLite) -- M3.

Persists the full loop so AEGIS gets faster and cheaper each time it is
attacked: campaign -> candidates -> gate outcomes -> promoted rule -> effect.
On a repeat campaign it recognises the signature and REUSES the proven rule
(no regeneration, no full gate) -> the >=10x repeat speedup. On a variant it
tries generalising an existing rule before synthesising fresh, and records
which happened.

A campaign SIGNATURE is a stable fingerprint of what the attack *is*, so a
repeat matches exactly and a variant matches by class: it is built from the
attack class plus the targeted endpoint shapes (ids collapsed to {id}), never
from the literal payload -- so a re-encoded or reworded variant still matches
the class.

SQLite, stdlib only. The store is advisory data for the deliberator; nothing
here enforces (invariant 3). Schema is created on first use.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "memory" / "aegis.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, signature TEXT, attack_class TEXT, endpoints TEXT, dossier TEXT);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER, ir_id TEXT, mechanism TEXT, verdict TEXT,
    rejected_at TEXT, stages TEXT);
CREATE TABLE IF NOT EXISTS rules (
    ir_id TEXT PRIMARY KEY, signature TEXT, attack_class TEXT, mechanism TEXT,
    ir TEXT, status TEXT, promoted_ts REAL, last_matched_ts REAL,
    match_count INTEGER DEFAULT 0, ttl_s INTEGER);
CREATE TABLE IF NOT EXISTS outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER, source TEXT, rule_ir_id TEXT, ttm_s REAL, ts REAL);
CREATE INDEX IF NOT EXISTS idx_rules_sig ON rules(signature);
CREATE INDEX IF NOT EXISTS idx_rules_class ON rules(attack_class);
"""


def signature(attack_class: str, endpoints: list[str]) -> str:
    """Stable campaign fingerprint: class + sorted endpoint shapes."""
    eps = sorted(e for e in endpoints if e not in ("", "/") and not e.startswith("/socket.io"))
    raw = attack_class + "|" + "|".join(eps)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Memory:
    def __init__(self, db: Path = DEFAULT_DB):
        db.parent.mkdir(parents=True, exist_ok=True)
        self.con = sqlite3.connect(db)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        self.con.commit()

    def close(self) -> None:
        self.con.close()

    # --- recording ---
    def record_campaign(self, dossier: dict) -> tuple[int, str]:
        cls = (dossier.get("techniques") or [dossier.get("attack_class", "")])[0]
        eps = dossier.get("endpoints", [])
        sig = signature(cls, eps)
        cur = self.con.execute(
            "INSERT INTO campaigns(ts,signature,attack_class,endpoints,dossier) VALUES(?,?,?,?,?)",
            (time.time(), sig, cls, json.dumps(eps), json.dumps(dossier)))
        self.con.commit()
        return cur.lastrowid, sig

    def record_candidate(self, campaign_id: int, ir: dict, verdict: str,
                         rejected_at: str | None, stages: list) -> None:
        self.con.execute(
            "INSERT INTO candidates(campaign_id,ir_id,mechanism,verdict,rejected_at,stages)"
            " VALUES(?,?,?,?,?,?)",
            (campaign_id, ir.get("id"), ir.get("mechanism"), verdict, rejected_at,
             json.dumps(stages)))
        self.con.commit()

    def promote_rule(self, ir: dict, sig: str) -> None:
        self.con.execute(
            "INSERT OR REPLACE INTO rules(ir_id,signature,attack_class,mechanism,ir,"
            "status,promoted_ts,last_matched_ts,match_count,ttl_s)"
            " VALUES(?,?,?,?,?,?,?,?,COALESCE((SELECT match_count FROM rules WHERE ir_id=?),0),?)",
            (ir["id"], sig, ir["attack_class"], ir["mechanism"], json.dumps(ir),
             "active", time.time(), time.time(), ir["id"], ir.get("ttl_s", 86400)))
        self.con.commit()

    def record_outcome(self, campaign_id: int, source: str, rule_ir_id: str | None,
                       ttm_s: float) -> None:
        self.con.execute(
            "INSERT INTO outcomes(campaign_id,source,rule_ir_id,ttm_s,ts) VALUES(?,?,?,?,?)",
            (campaign_id, source, rule_ir_id, ttm_s, time.time()))
        self.con.commit()

    # --- recall ---
    def rule_for_signature(self, sig: str) -> dict | None:
        """Exact repeat: an active promoted rule for this exact campaign."""
        row = self.con.execute(
            "SELECT ir FROM rules WHERE signature=? AND status='active' ORDER BY promoted_ts DESC",
            (sig,)).fetchone()
        return json.loads(row["ir"]) if row else None

    def rules_for_class(self, attack_class: str) -> list[dict]:
        """Variant candidates: active rules for the same attack class."""
        rows = self.con.execute(
            "SELECT ir FROM rules WHERE attack_class=? AND status='active'",
            (attack_class,)).fetchall()
        return [json.loads(r["ir"]) for r in rows]

    def touch_rule(self, ir_id: str) -> None:
        self.con.execute(
            "UPDATE rules SET last_matched_ts=?, match_count=match_count+1 WHERE ir_id=?",
            (time.time(), ir_id))
        self.con.commit()

    # --- garbage collection ---
    def gc(self, now: float | None = None, idle_s: float = 7 * 86400) -> list[str]:
        """Retire active rules not matched within idle_s (and past their TTL).
        Returns retired ir_ids. Real GC would re-validate before full removal;
        here we mark retired so the history is preserved."""
        now = now or time.time()
        rows = self.con.execute(
            "SELECT ir_id, last_matched_ts, promoted_ts, ttl_s FROM rules WHERE status='active'"
        ).fetchall()
        retired = []
        for r in rows:
            age = now - (r["last_matched_ts"] or r["promoted_ts"])
            if age > idle_s and age > r["ttl_s"]:
                self.con.execute("UPDATE rules SET status='retired' WHERE ir_id=?", (r["ir_id"],))
                retired.append(r["ir_id"])
        self.con.commit()
        return retired

    def stats(self) -> dict:
        c = self.con.execute
        return {
            "campaigns": c("SELECT COUNT(*) n FROM campaigns").fetchone()["n"],
            "candidates": c("SELECT COUNT(*) n FROM candidates").fetchone()["n"],
            "active_rules": c("SELECT COUNT(*) n FROM rules WHERE status='active'").fetchone()["n"],
            "outcomes_by_source": {r["source"]: r["n"] for r in c(
                "SELECT source, COUNT(*) n FROM outcomes GROUP BY source").fetchall()},
        }
