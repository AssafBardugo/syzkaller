from llm import (
    phase1_find_commit,
    phase2_define_causes,
)

CONFIDENCE_THRESHOLD = 0.9


def analyzeMismatch(task) -> bool:
    """
    Returns True if mismatch should be ignored.
    Populates task.analysis if True.
    """

    # ---------- Phase 1 ----------
    p1 = phase1_find_commit(task)
    if not p1 or p1["confidence"] < 0.7:
        return False

    # ---------- Phase 2 ----------
    p2 = phase2_define_causes(task, p1["commit_sha"])
    if not p2:
        return False

    confidence = min(p1["confidence"], p2["confidence"])

    if confidence < CONFIDENCE_THRESHOLD:
        return False

    # ---------- Attach analysis ----------
    task.analysis = {
        "commit": p1["commit_sha"],
        "change_version": p2["merge_version"],
        "rule": p2["ignore_rule"],
        "confidence": confidence,
        "explanation": p1["explanation"],
    }

    return True
