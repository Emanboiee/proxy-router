"""Fail-closed Windows engine discovery, independent of PID-file bookkeeping."""
import json
import subprocess


class EngineIdentityError(RuntimeError):
    """The process table could not prove engine identity safely."""


def find_windows_engine_pids(engine_binary: str, *, matches, runner) -> list[int]:
    script = (
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
        "@(Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,CommandLine) | ConvertTo-Json -Compress"
    )
    try:
        result = runner(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
        if result.returncode != 0:
            raise EngineIdentityError("cannot scan Windows engine processes")
        rows = json.loads(result.stdout)
        if not isinstance(rows, list):
            raise ValueError("expected a process array")
        binary_name = engine_binary.replace("\\", "/").rsplit("/", 1)[-1]
        pids = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("Name"), str):
                raise ValueError("invalid process row")
            if row["Name"].casefold() != binary_name.casefold():
                continue
            command = row.get("CommandLine")
            if not isinstance(command, str) or not command:
                raise EngineIdentityError("Windows engine command line is inaccessible")
            pid = row.get("ProcessId")
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
                raise ValueError("invalid process PID")
            if matches(command):
                pids.append(pid)
        return sorted(set(pids))
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError) as exc:
        raise EngineIdentityError(f"cannot scan Windows engine processes: {exc}") from exc
