#!/usr/bin/env python3
"""Deterministic lifecycle boundary scanner for autonomous agents."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


TEXT_SUFFIXES = {".cfg", ".conf", ".json", ".jsonl", ".md", ".py", ".sh", ".txt", ".yml", ".yaml"}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}
SECRET_VALUE_RE = re.compile(r"(?i)(api[_-]?key|password|private[_-]?key|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:-]{8,})")
KNOWN_SECRET_PREFIX_RE = re.compile(r"^(sk_|ghp_|xox[baprs]-|AIza)", re.IGNORECASE)

STAGES = ("input", "admission", "authority", "actuation", "receipt", "verification", "recovery", "retention")

KEYWORDS = {
    "input": ("context/", "inbox", "rss", "email", "transcript", "visitor", "suggestion", "webhook"),
    "admission": ("proposal", "firewall", "policy", "gate", "deny", "defer", "approve", "admit"),
    "authority": ("approval", "authority", "permission", "scope", "credential", "custody"),
    "actuation": ("curl", "git push", "subprocess", "os.system", "requests.", "mastodon", "reddit", "hn.py", "shell", "post"),
    "receipt": ("ledger", "receipt", "jsonl", "hash", "entry_hash", "prev_hash", "docket"),
    "verification": ("verify", "test", "check", "assert", "post-action", "evidence", "sha256"),
    "recovery": ("rollback", "retract", "correction", "revocation", "recover", "undo", "restore"),
    "retention": ("memory", "knowledge", "archive", "retention", "log", "output/"),
}

SEVERITY = {"ok": 0, "thin": 1, "missing": 2, "stale": 3, "collapsed": 4}


@dataclass
class Evidence:
    path: str
    reason: str


@dataclass
class Stage:
    status: str = "missing"
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: str) -> dt.datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def read_text_safely(path: Path) -> str:
    if path.name.startswith(".") or path.suffix.lower() not in TEXT_SUFFIXES:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:80_000]
    except OSError:
        return ""


def relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def discover_files(root: Path) -> list[tuple[Path, str, str]]:
    files: list[tuple[Path, str, str]] = []
    for path in sorted(root.rglob("*")):
        if should_skip(path) or not path.is_file():
            continue
        rel = relative(root, path)
        files.append((path, rel, read_text_safely(path)))
    return files


def has_keyword(rel: str, text: str, stage: str) -> str | None:
    haystack = f"{rel}\n{text}".lower()
    for keyword in KEYWORDS[stage]:
        if keyword in haystack:
            return keyword
    return None


def detect_stale_approval(text: str, now: dt.datetime) -> bool:
    lower = text.lower()
    if "approval" not in lower and "expires" not in lower:
        return False
    for key in ("expires_at", "expiry", "expires"):
        for match in re.finditer(rf'"?{key}"?\s*[:=]\s*"?([^",\n]+)', text, flags=re.IGNORECASE):
            parsed = parse_time(match.group(1))
            if parsed and parsed < now:
                return True
    return False


def contains_collapsed_secret(rel: str, text: str) -> bool:
    if Path(rel).name.startswith("."):
        return False
    for match in SECRET_VALUE_RE.finditer(text):
        value = match.group(2).strip().strip("'\"")
        if is_likely_secret_value(value):
            return True
    return False


def is_likely_secret_value(value: str) -> bool:
    lower = value.lower()
    if KNOWN_SECRET_PREFIX_RE.search(value):
        return True
    if "secret_value" in lower or "private_key" in lower:
        return True
    if re.fullmatch(r"[a-z][a-z0-9-]{3,32}-token", lower):
        return False
    if re.fullmatch(r"[a-z][a-z0-9-]{3,32}-secret", lower):
        return False
    classes = sum(
        [
            bool(re.search(r"[a-z]", value)),
            bool(re.search(r"[A-Z]", value)),
            bool(re.search(r"\d", value)),
            bool(re.search(r"[+/=_:.:-]", value)),
        ]
    )
    return len(value) >= 24 and classes >= 3


def stage_status(stage: str, evidence: list[Evidence], files: list[tuple[Path, str, str]], now: dt.datetime) -> Stage:
    result = Stage(evidence=evidence)
    if stage == "authority":
        stale = [rel for _, rel, text in files if detect_stale_approval(text, now)]
        collapsed = [rel for _, rel, text in files if contains_collapsed_secret(rel, text)]
        if not evidence and not stale and not collapsed:
            return result
        result.status = "ok"
        if len(evidence) == 1:
            result.status = "thin"
            result.notes.append("Only one weak signal found for this lifecycle stage.")
        if stale:
            result.status = "stale"
            result.notes.append("Approval-like artifact appears expired: " + ", ".join(stale[:3]))
        if collapsed:
            result.status = "collapsed"
            result.notes.append("Credential-like value appears inside ordinary repo text: " + ", ".join(collapsed[:3]))
        return result

    if not evidence:
        return result

    result.status = "ok"
    if stage in {"admission", "verification", "recovery"} and len(evidence) == 1:
        result.status = "thin"
        result.notes.append("Only one weak signal found for this lifecycle stage.")
    if stage == "recovery":
        manual_recovery_markers = [
            rel
            for _, rel, text in files
            if "manual drills still needed" in text.lower() or "manual recovery" in text.lower()
        ]
        if manual_recovery_markers:
            result.status = "thin"
            result.notes.append(
                "Recovery evidence names manual follow-up still needed: " + ", ".join(manual_recovery_markers[:3])
            )

    return result


def build_pathway(root: Path, files: list[tuple[Path, str, str]], now: dt.datetime) -> dict[str, Any]:
    stages: dict[str, Stage] = {}
    for stage in STAGES:
        evidence: list[Evidence] = []
        for _, rel, text in files:
            keyword = has_keyword(rel, text, stage)
            if keyword:
                evidence.append(Evidence(rel, f"matched `{keyword}`"))
        stages[stage] = stage_status(stage, evidence[:8], files, now)

    findings: list[dict[str, str]] = []
    for stage_name, stage in stages.items():
        if stage.status != "ok":
            findings.append(
                {
                    "stage": stage_name,
                    "severity": stage.status,
                    "detail": "; ".join(stage.notes) if stage.notes else f"No durable {stage_name} boundary evidence found.",
                }
            )

    risk = "low"
    worst = max((SEVERITY.get(item["severity"], 0) for item in findings), default=0)
    if worst >= 4:
        risk = "critical"
    elif worst == 3:
        risk = "high"
    elif worst == 2:
        risk = "medium"

    return {
        "pathway_id": root.name,
        "target": str(root),
        "risk": risk,
        "stages": {
            name: {
                "status": stage.status,
                "evidence": [{"path": ev.path, "reason": ev.reason} for ev in stage.evidence],
                "notes": stage.notes,
            }
            for name, stage in stages.items()
        },
        "findings": findings,
    }


def previous_hash(ledger: Path) -> str:
    if not ledger.exists():
        return "0" * 64
    lines = [line for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return "0" * 64
    try:
        return json.loads(lines[-1]).get("entry_hash", "0" * 64)
    except json.JSONDecodeError:
        return "0" * 64


def append_ledger(outdir: Path, target: Path, boundary_map: dict[str, Any], generated_at: str) -> str:
    ledger = outdir / "lifecycle-ledger.jsonl"
    entry = {
        "timestamp": generated_at,
        "target": str(target),
        "pathways": len(boundary_map["pathways"]),
        "risk_counts": boundary_map["risk_counts"],
        "map_hash": sha256_text(stable_json(boundary_map)),
        "previous_hash": previous_hash(ledger),
    }
    entry["entry_hash"] = sha256_text(stable_json(entry))
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(stable_json(entry) + "\n")
    return entry["entry_hash"]


def write_outputs(outdir: Path, boundary_map: dict[str, Any], ledger_hash: str) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "boundary-map.json").write_text(json.dumps(boundary_map, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    docket = ["# Boundary Docket", "", f"- generated: `{boundary_map['generated_at']}`", f"- ledger head: `{ledger_hash}`", ""]
    docket.extend(["| Pathway | Risk | Missing/Weak Stages |", "|---|---|---|"])
    for pathway in boundary_map["pathways"]:
        weak = ", ".join(f"{f['stage']}:{f['severity']}" for f in pathway["findings"]) or "none"
        docket.append(f"| `{pathway['pathway_id']}` | `{pathway['risk']}` | {weak} |")
    (outdir / "boundary-docket.md").write_text("\n".join(docket) + "\n", encoding="utf-8")

    gaps = ["# Lifecycle Gap Report", ""]
    found = False
    for pathway in boundary_map["pathways"]:
        if not pathway["findings"]:
            continue
        found = True
        gaps.append(f"## {pathway['pathway_id']} ({pathway['risk']})")
        gaps.append("")
        for finding in pathway["findings"]:
            gaps.append(f"- `{finding['stage']}` {finding['severity']}: {finding['detail']}")
        gaps.append("")
    if not found:
        gaps.append("No lifecycle gaps found.")
    (outdir / "gaps.md").write_text("\n".join(gaps), encoding="utf-8")


def scan(target: Path, outdir: Path, now: dt.datetime) -> dict[str, Any]:
    target = target.resolve()
    files = discover_files(target)
    pathway = build_pathway(target, files, now)
    risks: dict[str, int] = {}
    risks[pathway["risk"]] = 1
    boundary_map = {
        "generated_at": now.isoformat(),
        "target": str(target),
        "file_count": len(files),
        "model": "input -> admission -> authority -> actuation -> receipt -> verification -> recovery -> retention",
        "risk_counts": risks,
        "pathways": [pathway],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    ledger_hash = append_ledger(outdir, target, boundary_map, now.isoformat())
    boundary_map["ledger_head"] = ledger_hash
    write_outputs(outdir, boundary_map, ledger_hash)
    return boundary_map


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan an agent repo for lifecycle boundary gaps.")
    parser.add_argument("target", nargs="?", default=".", help="Target repo or workspace to scan.")
    parser.add_argument("--out", default="output", help="Directory for boundary-map.json, docket, gaps, and ledger.")
    parser.add_argument("--now", default=None, help="Deterministic ISO timestamp for tests.")
    args = parser.parse_args()

    now = parse_time(args.now) if args.now else utcnow()
    if now is None:
        parser.error("--now must be an ISO timestamp")
    result = scan(Path(args.target), Path(args.out), now)
    print(f"scanned {result['file_count']} files; risk={result['pathways'][0]['risk']}; ledger={result['ledger_head'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
