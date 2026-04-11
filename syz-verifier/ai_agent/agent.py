#!/usr/bin/env python3
import argparse
import json
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

from mismatch_task import MismatchTask
from ignore_writer import append_ignore_rule, DuplicateRuleError
from llm_support import analyze_mismatch_with_llm

# Default behavior: exit when new/ is empty (same as your original behavior).
EXIT_ON_EMPTY_NEW_DIR = True

QUEUE_ROOT      = Path("agent/queue")
NEW_DIR         = QUEUE_ROOT / "new"
PROCESSING_DIR  = QUEUE_ROOT / "processing"
DONE_DIR        = QUEUE_ROOT / "done"
FAILED_DIR      = QUEUE_ROOT / "failed"
REJECTED_DIR    = QUEUE_ROOT / "rejected"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="syz-verifier AI agent: triage mismatches and update ignore rules")
    p.add_argument("--no-write", action="store_true",
                   help="Dry-run: do not modify manual_ignore_list.yaml, only write decision JSON outputs")
    p.add_argument("--ignore-file", default="manual_ignore_list.yaml",
                   help="Path to ignore rules YAML (default: manual_ignore_list.yaml)")
    p.add_argument("--once", action="store_true",
                   help="Process at most one job and exit")
    p.add_argument("--loop", action="store_true",
                   help="Keep polling new/ instead of exiting when empty")
    p.add_argument("--min-confidence", type=float, default=0.90,
                   help="Minimum confidence to auto-ignore and write rule (default: 0.90)")
    return p.parse_args()


def agentLoop(cfg: argparse.Namespace):
    global EXIT_ON_EMPTY_NEW_DIR
    EXIT_ON_EMPTY_NEW_DIR = not cfg.loop

    while True:
        job_path = claimNextJob()
        if job_path is None:
            if EXIT_ON_EMPTY_NEW_DIR:
                break
            time.sleep(0.2)
            continue
        processOneJob(job_path, cfg)

        if cfg.once:
            break


def claimNextJob() -> Optional[Path]:
    """
    Atomically move one job from new/ to processing/.
    Returns the path in processing/, or None if no job available.
    """
    NEW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSING_DIR.mkdir(parents=True, exist_ok=True)

    for job in NEW_DIR.iterdir():
        if not job.is_file():
            continue

        target = PROCESSING_DIR / job.name
        try:
            os.rename(job, target)  # atomic on same filesystem
            return target
        except FileNotFoundError:
            # Lost the race: someone else took it
            continue
        except OSError:
            # Permission / FS issue – skip, don't die
            continue

    return None


def processOneJob(path: Path, cfg: argparse.Namespace):
    try:
        job = MismatchTask(path)

        result = analyzeMismatch(job, min_confidence=cfg.min_confidence)

        # Always write the structured decision JSON to done/ or rejected/
        if result["decision"] == "ignore":
            # Optionally write ignore rule (unless dry-run)
            if result.get("rule") and not cfg.no_write:
                try:
                    append_ignore_rule(
                        ignore_file=Path(cfg.ignore_file),
                        rule=result["rule"],
                        commit_sha=result.get("commit_sha"),
                        confidence=float(result.get("confidence", 0.0)),
                        reasoning=result.get("reasoning", ""),
                    )
                except DuplicateRuleError as dup:
                    # Treat duplicate as success, but explain in reasoning.
                    result["reasoning"] += f"\n\n[agent] rule already exists: {dup}"
            else:
                if cfg.no_write:
                    result["reasoning"] += "\n\n[agent] dry-run enabled: not writing ignore file."
                else:
                    result["reasoning"] += "\n\n[agent] ignore decision but no rule produced."

            writeResult(path, result, DONE_DIR)
            path.unlink()

        elif result["decision"] == "reject":
            writeResult(path, result, REJECTED_DIR)
            path.unlink()
        else:
            raise ValueError(f"unknown decision: {result['decision']}")

    except Exception as e:
        FAILED_DIR.mkdir(parents=True, exist_ok=True)
        path.rename(FAILED_DIR / path.name)
        print(f"[agent] failed processing {path.name}: {e}")


def analyzeMismatch(job: MismatchTask, *, min_confidence: float) -> Dict[str, Any]:
    """
    LLM-backed analysis. Returns:
      {
        "decision": "ignore" | "reject",
        "confidence": float,
        "reasoning": str,
        "rule": dict | None,
        "commit_sha": str | None,
      }
    """
    try:
        analysis = analyze_mismatch_with_llm(job)
    except Exception as e:
        return {
            "decision": "reject",
            "confidence": 0.0,
            "reasoning": f"LLM analysis failed: {e}",
            "rule": None,
            "commit_sha": None,
        }

    confidence = float(analysis.get("confidence", 0.0))
    commit_sha = analysis.get("commit_sha")
    rule = analysis.get("rule")

    if confidence >= min_confidence and rule:
        return {
            "decision": "ignore",
            "confidence": confidence,
            "reasoning": analysis.get("reasoning", ""),
            "rule": rule,
            "commit_sha": commit_sha,
        }

    # Below threshold => reject (for human triage)
    why = analysis.get("reasoning", "")
    if confidence < min_confidence:
        why = f"Confidence {confidence:.2f} < threshold {min_confidence:.2f}.\n\n" + why

    return {
        "decision": "reject",
        "confidence": confidence,
        "reasoning": why,
        "rule": None,
        "commit_sha": commit_sha,
    }


def writeResult(input_path: Path, result: dict, target_dir: Path):
    target_dir.mkdir(parents=True, exist_ok=True)

    output = {
        "input_file": input_path.name,
        "decision": result["decision"],
        "confidence": result["confidence"],
        "reasoning": result["reasoning"],
        "rule": result.get("rule"),
        "commit_sha": result.get("commit_sha"),
        "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    out_path = target_dir / input_path.name
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    cfg = parse_args()
    agentLoop(cfg)
