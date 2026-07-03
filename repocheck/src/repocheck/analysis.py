import json
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repocheck.vm import EphemeralVM

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


def run_analysis(url: str, timeout: float = 300.0) -> AnalysisReport:
    with EphemeralVM(launch_timeout=180.0) as vm:
        bootstrap_result = vm.run(_BOOTSTRAP_COMMAND, timeout=240.0)
        if bootstrap_result.returncode != 0:
            return AnalysisReport(
                clone_succeeded=False,
                error=f"bootstrap failed: {bootstrap_result.stderr.strip()}",
            )

        clone_result = vm.run(
            ["git", "clone", "--", url, _REMOTE_REPO_PATH], timeout=timeout
        )
        if clone_result.returncode != 0:
            return AnalysisReport(
                clone_succeeded=False,
                error=f"clone failed: {clone_result.stderr.strip()}",
            )

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

        local_report_path = _local_temp_report_path()
        vm.pull_file(_REMOTE_REPORT_PATH, local_report_path)
        payload = json.loads(local_report_path.read_text())
        local_report_path.unlink(missing_ok=True)

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
