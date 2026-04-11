#!/usr/bin/env python3
"""
LLM-backed mismatch analysis.

Important: this module is written to match your current JSON jobs produced by mismatch.go:
it contains syscall, call_line, args, kernel versions and errnos, but NOT the full program sequence.
See mismatch.go mismatchJSON payload.\n
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from openai import OpenAI

MODEL = os.getenv("SYZ_AGENT_MODEL", "gpt-5.2")
client = OpenAI()

KERNEL_COMMIT_PREFIX = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id="


def _extract_sha(s: str) -> Optional[str]:
    m = re.search(r"\b[0-9a-f]{40}\b", s, re.IGNORECASE)
    return m.group(0).lower() if m else None


def _ensure_kernelorg_only(urls: List[str]) -> List[str]:
    good = []
    for u in urls:
        if u.startswith(KERNEL_COMMIT_PREFIX):
            good.append(u)
    return good


def analyze_mismatch_with_llm(job) -> Dict[str, Any]:
    """Return a dict with commit_sha, confidence, reasoning, and ignore rule."""
    # Phase 1: find commit
    p1 = _phase1_find_commit(job)
    if not p1.get("commit_sha"):
        return {
            "commit_sha": None,
            "confidence": float(p1.get("confidence", 0.0)),
            "reasoning": p1.get("explanation", "No commit found."),
            "rule": None,
        }

    # Phase 2: derive rule
    p2 = _phase2_define_causes(job, p1["commit_sha"])

    # Combine confidence conservatively
    conf = min(float(p1.get("confidence", 0.0)), float(p2.get("confidence", 0.0)))

    reasoning = (
        f"Commit: {p1['commit_sha']}\n"
        f"Phase1: {p1.get('explanation','').strip()}\n\n"
        f"Phase2 notes: {p2.get('notes','').strip()}"
    ).strip()

    rule = p2.get("ignore_rule")
    if rule:
        # Ensure mandatory keys (match manual_ignore_list.yaml style)
        # call.one_of, change_version, old_errno, new_errno, match.args...
        rule.setdefault("call", {"one_of": [job.mismatch_call.name]})
        rule.setdefault("match", {"args": {"any": True}})
        rule.setdefault("change_version", p2.get("merge_version", ""))
        rule.setdefault("old_errno", job.kernel0.errno)
        rule.setdefault("new_errno", job.kernel1.errno)

    return {
        "commit_sha": p1["commit_sha"],
        "confidence": conf,
        "reasoning": reasoning,
        "rule": rule,
    }


def _phase1_find_commit(job) -> Dict[str, Any]:
    prompt = f"""You are analyzing a syz-verifier errno mismatch.

        Kernel0 version: {job.kernel0.kernel_version}
        Kernel1 version: {job.kernel1.kernel_version}

        Investigate ONLY the {job.mismatch_call.name} call.

        Mismatch:
        - call_line: {getattr(job, 'call_line', None) or 'N/A'}
        - args: {job.mismatch_call.args}
        - old_errno (kernel0): {job.kernel0.errno}
        - new_errno (kernel1): {job.kernel1.errno}

        Task:
        Find the Linux kernel commit that explains this errno difference.

        Rules:
        - Search ONLY this repo: {KERNEL_COMMIT_PREFIX}
        - Do not use other sources.
        - Output JSON with:
        - commit_sha (40-hex) or empty string
        - confidence (0..1)
        - explanation (short)
        - evidence_urls (list of ONLY git.kernel.org commit URLs)
    """

    schema = {
        "type": "object",
        "properties": {
            "commit_sha": {"type": "string"},
            "confidence": {"type": "number"},
            "explanation": {"type": "string"},
            "evidence_urls": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["commit_sha", "confidence", "explanation", "evidence_urls"],
        "additionalProperties": False,
    }

    resp = client.responses.create(
        model=MODEL,
        tools=[{"type": "web_search"}],
        input=prompt,
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "phase1_commit", "schema": schema, "strict": True},
        },
    )
    data = json.loads(resp.output_text)
    sha = (data.get("commit_sha") or "").strip().lower()
    if sha and not re.fullmatch(r"[0-9a-f]{40}", sha):
        sha = ""

    urls = _ensure_kernelorg_only(data.get("evidence_urls", []))
    if data.get("evidence_urls") and not urls:
        # model used other sources
        sha = ""

    return {
        "commit_sha": sha,
        "confidence": float(data.get("confidence", 0.0)),
        "explanation": data.get("explanation", ""),
        "evidence_urls": urls,
    }


def _phase2_define_causes(job, sha: str) -> Dict[str, Any]:
    prompt = f"""Based on commit {sha}, provide the following JSON:

        1) merge_version: first Linux version (major.minor.patch) that contains this commit.
        2) essential_params: which params of {job.mismatch_call.name} are essential for this diff.
        3) necessary_prev_calls: if depends on previous calls, which ones (can be empty).
        4) ignore_rule: propose a rule compatible with manual_ignore_list.yaml (JSON form).
        - call: {{ one_of: [...] }}
        - change_version: "x.y.z"
        - old_errno / new_errno as strings
        - match: {{ args: ... }}
        5) confidence: 0..1
        6) notes: short human explanation

        Constraints:
        - Only derive from {KERNEL_COMMIT_PREFIX} pages.
        - If unsure, keep ignore_rule narrow and lower confidence.
    """

    schema = {
        "type": "object",
        "properties": {
            "merge_version": {"type": "string"},
            "essential_params": {"type": "array", "items": {"type": "string"}},
            "necessary_prev_calls": {"type": "array", "items": {"type": "string"}},
            "ignore_rule": {"type": "object"},
            "confidence": {"type": "number"},
            "notes": {"type": "string"},
        },
        "required": ["merge_version", "essential_params", "necessary_prev_calls", "ignore_rule", "confidence", "notes"],
        "additionalProperties": False,
    }

    resp = client.responses.create(
        model=MODEL,
        tools=[{"type": "web_search"}],
        input=prompt,
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "phase2_rule", "schema": schema, "strict": True},
        },
    )
    return json.loads(resp.output_text)
