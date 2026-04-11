#!/usr/bin/env python3
"""
Append ignore rules to manual_ignore_list.yaml with:
- dry-run support handled by caller
- duplicate rule detection
- commit URL + confidence as YAML comments
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class DuplicateRuleError(RuntimeError):
    pass


def _canonical(obj: Any) -> Any:
    """Return a JSON-like object with stable ordering for hashing/comparison."""
    if isinstance(obj, dict):
        return {k: _canonical(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonical(x) for x in obj]
    return obj


def _rule_fingerprint(rule: Dict[str, Any]) -> str:
    # Ignore purely cosmetic differences by canonicalizing keys and YAML types.
    canon = _canonical(rule)
    raw = yaml.safe_dump(canon, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_rules(ignore_file: Path) -> List[Dict[str, Any]]:
    if not ignore_file.exists():
        return []
    data = yaml.safe_load(ignore_file.read_text(encoding="utf-8")) or {}
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("ignore YAML must contain top-level 'rules:' list")
    return rules


def _ensure_header(ignore_file: Path):
    if ignore_file.exists():
        return
    ignore_file.write_text(
        "# Known call semantic changes that may cause false-positive diffs in syz-verifier\n"
        "# Rules are matched against string representations of the call lines\n"
        "# Errnos are compared as STRINGS containing NUMERIC errno values only\n\n"
        "rules:\n",
        encoding="utf-8",
    )


def _format_rule_as_yaml_list_item(rule: Dict[str, Any]) -> str:
    """Format a single rule as an indented YAML list item under 'rules:'"""
    # Dump dict only, then convert to list item.
    dumped = yaml.safe_dump(rule, sort_keys=False).rstrip("\n")
    lines = dumped.splitlines()
    if not lines:
        return ""
    out = []
    out.append("  - " + lines[0])
    for line in lines[1:]:
        out.append("    " + line)
    return "\n".join(out) + "\n"


def append_ignore_rule(
    *,
    ignore_file: Path,
    rule: Dict[str, Any],
    commit_sha: Optional[str],
    confidence: float,
    reasoning: str,
):
    """
    Append rule to ignore_file, unless an identical rule already exists.

    The rule MUST match the Go ignore.go schema. We do NOT add new YAML keys.
    Instead, we add YAML comments preceding the rule.
    """
    _ensure_header(ignore_file)

    existing = _load_rules(ignore_file)
    fp_new = _rule_fingerprint(rule)

    for idx, r in enumerate(existing):
        if not isinstance(r, dict):
            continue
        if _rule_fingerprint(r) == fp_new:
            raise DuplicateRuleError(f"existing rule index={idx}")

    # Comments (YAML comments are safe: ignored by Go YAML parser).
    commit_url = None
    if commit_sha:
        commit_url = (
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id="
            + commit_sha
        )

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    comments = []
    comments.append(f"  # ai: added_at={now}")
    if commit_url:
        comments.append(f"  # ai: commit={commit_url}")
    comments.append(f"  # ai: confidence={confidence:.2f}")

    # Keep the reasoning short in YAML (avoid huge diffs). First line only.
    reason_line = (reasoning or "").strip().splitlines()[0] if reasoning else ""
    if reason_line:
        # truncate
        if len(reason_line) > 160:
            reason_line = reason_line[:157] + "..."
        comments.append(f"  # ai: why={reason_line}")

    snippet = "\n".join(comments) + "\n" + _format_rule_as_yaml_list_item(rule)

    # Append at end of file (preserves existing formatting/comments).
    with ignore_file.open("a", encoding="utf-8") as f:
        # Ensure a blank line before new block for readability.
        if not ignore_file.read_text(encoding="utf-8").endswith("\n\n"):
            f.write("\n")
        f.write(snippet)
