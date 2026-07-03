import json
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from repocheck.vm import (
    EphemeralVM,
    VMCleanupError,
    VMCommandTimeout,
    VMLaunchError,
    VMTransferError,
)

_VM_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "vm_scripts"
_ANALYZE_SCRIPT = _VM_SCRIPTS_DIR / "analyze.py"

_REMOTE_REPO_PATH = "/home/ubuntu/repo"
_REMOTE_SCRIPT_PATH = "/home/ubuntu/analyze.py"
_REMOTE_REPORT_PATH = "/home/ubuntu/report.json"

_BOOTSTRAP_COMMAND = [
    "bash",
    "-c",
    # ports.ubuntu.com's WAF returns 403 to apt's default "Debian APT-HTTP/..."
    # User-Agent (observed directly against a real Multipass 24.04 VM) for
    # BOTH the index update and package downloads; a generic User-Agent is
    # accepted, so override it for every apt-get invocation.
    "sudo apt-get update -qq -o Acquire::http::User-Agent=Mozilla/5.0 && "
    "sudo apt-get install -y -qq -o Acquire::http::User-Agent=Mozilla/5.0 "
    "git python3-pip nodejs npm strace && "
    # Ubuntu 24.04 marks the system Python as externally-managed (PEP 668),
    # refusing a bare `pip install`. This VM is single-purpose and disposable,
    # so installing straight into the system Python is acceptable here.
    "pip3 install --quiet --break-system-packages detect-secrets",
]

# Matches git's progress-meter lines (e.g. "Updating files:  43% (180/414)"),
# which are noisy and not useful inside an error message.
_GIT_PROGRESS_LINE = re.compile(
    r"^\s*(Updating files|Receiving objects|Resolving deltas|"
    r"Counting objects|Compressing objects):\s+\d+%"
)


def _clean_git_stderr(stderr: str) -> str:
    meaningful = [
        line
        for line in stderr.splitlines()
        if line.strip() and not _GIT_PROGRESS_LINE.match(line)
    ]
    cleaned = "\n".join(meaningful).strip()
    return cleaned or stderr.strip()


def _default_progress_reporter(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@dataclass
class AnalysisReport:
    clone_succeeded: bool
    malicious_patterns: list[dict[str, Any]] = field(default_factory=list)
    git_findings: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    dynamic_attempted: bool = False
    dynamic_command: list[str] | None = None
    dynamic_exit_code: int | None = None
    dynamic_timed_out: bool = False
    network_cutoff_applied: bool | None = None
    network_connect_attempts: list[str] = field(default_factory=list)
    error: str | None = None


def _local_temp_report_path() -> Path:
    return Path(tempfile.gettempdir()) / f"repocheck-report-{uuid.uuid4().hex}.json"


def run_analysis(
    url: str,
    timeout: float = 600.0,
    on_progress: Callable[[str], None] = _default_progress_reporter,
) -> AnalysisReport:
    on_progress("Launching disposable analysis VM (this can take a minute)...")
    clone_succeeded = False
    try:
        with EphemeralVM(launch_timeout=180.0) as vm:
            on_progress("Installing analysis tools inside the VM (git, npm, detect-secrets)...")
            bootstrap_result = vm.run(_BOOTSTRAP_COMMAND, timeout=240.0)
            if bootstrap_result.returncode != 0:
                return AnalysisReport(
                    clone_succeeded=False,
                    error=f"bootstrap failed: {bootstrap_result.stderr.strip()}",
                )

            on_progress("Cloning the repository inside the isolated VM...")
            clone_result = vm.run(
                ["git", "clone", "--", url, _REMOTE_REPO_PATH], timeout=timeout
            )
            if clone_result.returncode != 0:
                return AnalysisReport(
                    clone_succeeded=False,
                    error=f"clone failed: {_clean_git_stderr(clone_result.stderr)}",
                )
            clone_succeeded = True

            on_progress("Running static and dynamic analysis (network is cut before any build step)...")
            vm.push_file(_ANALYZE_SCRIPT, _REMOTE_SCRIPT_PATH)

            analyze_result = vm.run(
                ["python3", _REMOTE_SCRIPT_PATH, _REMOTE_REPO_PATH, _REMOTE_REPORT_PATH],
                timeout=timeout,
            )
            if analyze_result.returncode != 0:
                return AnalysisReport(
                    clone_succeeded=True,
                    error=f"analysis script failed: {analyze_result.stderr.strip()}",
                )

            on_progress("Collecting results and destroying the VM...")
            local_report_path = _local_temp_report_path()
            vm.pull_file(_REMOTE_REPORT_PATH, local_report_path)
            payload = json.loads(local_report_path.read_text())
            local_report_path.unlink(missing_ok=True)
    except VMLaunchError as exc:
        return AnalysisReport(
            clone_succeeded=False, error=f"failed to launch the analysis VM: {exc}"
        )
    except VMCommandTimeout as exc:
        return AnalysisReport(
            clone_succeeded=clone_succeeded,
            error=f"analysis did not finish within the {timeout:.0f}s timeout: {exc}",
        )
    except VMTransferError as exc:
        return AnalysisReport(
            clone_succeeded=clone_succeeded,
            error=f"failed to transfer files to/from the analysis VM: {exc}",
        )
    except VMCleanupError as exc:
        return AnalysisReport(
            clone_succeeded=clone_succeeded,
            error=f"failed to destroy the analysis VM after analysis: {exc}",
        )

    dynamic = payload.get("dynamic", {})
    return AnalysisReport(
        clone_succeeded=True,
        malicious_patterns=payload.get("malicious_patterns", []),
        git_findings=payload.get("git_findings", []),
        secrets=payload.get("secrets", []),
        dynamic_attempted=dynamic.get("attempted", False),
        dynamic_command=dynamic.get("command"),
        dynamic_exit_code=dynamic.get("exit_code"),
        dynamic_timed_out=dynamic.get("timed_out", False),
        network_cutoff_applied=dynamic.get("network_cutoff_applied"),
        network_connect_attempts=dynamic.get("network_connect_attempts", []),
    )
