from __future__ import annotations

import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROJECT_ROOT / "powershell" / "Run-ZTVP.ps1"


def open_cli_runner() -> None:
    if not RUNNER_PATH.exists():
        raise FileNotFoundError(f"Run-ZTVP.ps1 not found: {RUNNER_PATH}")

    creationflags = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0

    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-NoExit",
            "-File",
            str(RUNNER_PATH),
        ],
        cwd=str(PROJECT_ROOT),
        creationflags=creationflags,
    )
