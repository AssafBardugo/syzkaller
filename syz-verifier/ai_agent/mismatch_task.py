#!/usr/bin/env python3
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
from pathlib import Path

@dataclass(frozen=True)
class Call:
    name: str
    args: list[str]
    prog_index: int
    call_index: int

@dataclass(frozen=True)
class KernelResult:
    kernel_version: str
    errno: str

class TaskState(Enum):
    NEW = "new"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"
    REJECTED = "rejected"

@dataclass
class MismatchTask:
    task_id: str                    # stable hash
    created_at: float

    # Immutable context
    mismatch_call: Call
    kernel0: KernelResult
    kernel1: KernelResult
    
    # Mutable
    state: TaskState
    attempts: int
    last_error: str | None
    decision: dict | None
    analysis: str

    def __init__(self, path: Path):
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        required = ["created_at", "syscall", "kernel0", "kernel1"]
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")

        created_at = _parseCreatedAt(data["created_at"])
        prog_index = int(data.get("prog_index", 0))
        call_index = int(data.get("call_index", 0))

        args = data.get("args", [])
        if not isinstance(args, list):
            raise ValueError("args must be a list")

        kernel0 = _parseKernel(data["kernel0"])
        kernel1 = _parseKernel(data["kernel1"])

        call_name = str(data["syscall"])
        self.task_id = _hashPayload(
            {
                "syscall": call_name,
                "args": args,
                "kernel0": data["kernel0"],
                "kernel1": data["kernel1"],
            }
        )
        self.created_at = created_at
        self.mismatch_call = Call(
            name=call_name,
            args=[str(arg) for arg in args],
            prog_index=prog_index,
            call_index=call_index,
        )
        self.kernel0 = kernel0
        self.kernel1 = kernel1
        self.state = TaskState.NEW
        self.attempts = 0
        self.last_error = None
        self.decision = None
        self.analysis = None


def _parseKernel(data: dict) -> KernelResult:
    if not isinstance(data, dict):
        raise ValueError("kernel data must be an object")
    if "version" not in data or "errno" not in data:
        raise ValueError("kernel data must include version and errno")
    return KernelResult(kernel_version=str(data["version"]), errno=str(data["errno"]))


def _parseCreatedAt(value: str) -> float:
    if not value:
        return 0.0
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    if "." in value:
        head, tail = value.split(".", 1)
        frac = tail
        tz_part = ""
        for idx, ch in enumerate(tail):
            if ch in "+-":
                frac = tail[:idx]
                tz_part = tail[idx:]
                break
        frac = (frac + "000000")[:6]
        value = f"{head}.{frac}{tz_part}"
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


def _hashPayload(payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(data).hexdigest()
