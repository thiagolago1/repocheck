import json
import os
import re
import shutil
import signal
import subprocess
import sys
import unicodedata
from pathlib import Path

MALICIOUS_PATTERNS = [
    ("curl_pipe_shell", re.compile(r"curl\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b")),
    ("wget_pipe_shell", re.compile(r"wget\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b")),
    ("js_eval_decoded", re.compile(r"eval\s*\(\s*(atob|Buffer\.from)\s*\(")),
    (
        "powershell_encoded_command",
        re.compile(r"powershell(\.exe)?\s+.*-[Ee]nc(odedCommand)?\b"),
    ),
    ("python_exec_base64", re.compile(r"exec\s*\(\s*base64\.b64decode")),
]

_MAX_FILE_SIZE_BYTES = 1_000_000


def _is_probably_binary(data: bytes) -> bool:
    return b"\x00" in data


def scan_malicious_patterns(repo_path: Path) -> list[dict]:
    findings = []
    for file_path in sorted(repo_path.rglob("*")):
        if not file_path.is_file():
            continue
        relative_path = file_path.relative_to(repo_path)
        if ".git" in relative_path.parts:
            continue
        try:
            if file_path.stat().st_size > _MAX_FILE_SIZE_BYTES:
                continue
            raw = file_path.read_bytes()
        except OSError:
            continue
        if _is_probably_binary(raw):
            continue
        text = raw.decode("utf-8", errors="ignore")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_name, pattern in MALICIOUS_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "rule": rule_name,
                            "file": str(relative_path),
                            "line": line_number,
                            "snippet": line.strip()[:200],
                        }
                    )
    return findings


def scan_git_specifics(repo_path: Path) -> list[dict]:
    findings = []

    gitmodules = repo_path / ".gitmodules"
    if gitmodules.is_file():
        for line_number, line in enumerate(
            gitmodules.read_text(errors="ignore").splitlines(), start=1
        ):
            if "ext::" in line:
                findings.append(
                    {
                        "rule": "gitmodules_ext_transport",
                        "file": ".gitmodules",
                        "line": line_number,
                        "snippet": line.strip()[:200],
                    }
                )

    gitattributes = repo_path / ".gitattributes"
    if gitattributes.is_file():
        for line_number, line in enumerate(
            gitattributes.read_text(errors="ignore").splitlines(), start=1
        ):
            if "filter=" in line:
                findings.append(
                    {
                        "rule": "gitattributes_custom_filter",
                        "file": ".gitattributes",
                        "line": line_number,
                        "snippet": line.strip()[:200],
                    }
                )

    root_git_path = repo_path / ".git"
    for path in sorted(repo_path.rglob(".git")):
        if path == root_git_path:
            continue
        findings.append(
            {
                "rule": "nested_git_path",
                "file": str(path.relative_to(repo_path)),
                "line": 0,
                "snippet": "",
            }
        )

    for path in sorted(repo_path.rglob("*")):
        relative_path = path.relative_to(repo_path)
        if ".git" in relative_path.parts:
            continue
        if any(unicodedata.category(ch) == "Cf" for ch in path.name):
            findings.append(
                {
                    "rule": "suspicious_filename_characters",
                    "file": str(relative_path),
                    "line": 0,
                    "snippet": "",
                }
            )

    return findings


def _resolve_detect_secrets_command() -> str:
    found = shutil.which("detect-secrets")
    if found:
        return found
    candidate = Path(sys.executable).parent / "detect-secrets"
    if candidate.is_file():
        return str(candidate)
    return "detect-secrets"


def scan_secrets(repo_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            [
                _resolve_detect_secrets_command(),
                "scan",
                "--all-files",
                "--exclude-files",
                r"(^|/)\.git/",
                ".",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(repo_path),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return [
            {
                "rule": "scanner_not_executed",
                "file": "",
                "line": 0,
                "snippet": f"detect-secrets unavailable: {exc}",
            }
        ]

    if result.returncode != 0:
        return [
            {
                "rule": "scanner_not_executed",
                "file": "",
                "line": 0,
                "snippet": f"detect-secrets failed: {result.stderr.strip()}",
            }
        ]

    payload = json.loads(result.stdout)
    findings = []
    for file_path, file_findings in payload.get("results", {}).items():
        for finding in file_findings:
            findings.append(
                {
                    "rule": f"secret_{finding['type'].lower().replace(' ', '_')}",
                    "file": file_path,
                    "line": finding["line_number"],
                    "snippet": "",
                }
            )
    return findings


def run(repo_path: Path, output_path: Path) -> None:
    report = {
        "malicious_patterns": scan_malicious_patterns(repo_path),
        "git_findings": scan_git_specifics(repo_path),
        "secrets": scan_secrets(repo_path),
        "dynamic": run_dynamic_step(repo_path),
    }
    output_path.write_text(json.dumps(report, indent=2))


def cut_network() -> dict:
    # A blanket `-P OUTPUT DROP` also blocks the response traffic of the
    # already-established SSH connection the host uses to manage the VM,
    # which makes the host perceive a hang until its own outer timeout
    # fires (observed live on a repo with nothing more than a
    # package.json). But a broad `--state ESTABLISHED,RELATED` accept lets
    # DNS leak through pre-cutoff conntrack UDP flows (observed live:
    # registry.npmjs.org resolved AFTER the cutoff) — a real
    # DNS-exfiltration hole. So the accept is scoped to exactly the
    # management channel: established TCP traffic FROM source port 22
    # (sshd's replies) and nothing else.
    result = subprocess.run(
        [
            "sudo",
            "bash",
            "-c",
            "iptables -P OUTPUT DROP && "
            "iptables -A OUTPUT -o lo -j ACCEPT && "
            "iptables -A OUTPUT -p tcp --sport 22 "
            "-m state --state ESTABLISHED -j ACCEPT",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {
        "applied": result.returncode == 0,
        "error": "" if result.returncode == 0 else result.stderr.strip(),
    }


# The root package's lifecycle scripts that `npm install` runs automatically.
# These — plus dependencies' own install/postinstall scripts, exercised via
# `npm rebuild` — are the actual code-execution attack surface of an install.
_NPM_ROOT_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def detect_ecosystem(repo_path: Path) -> str | None:
    if (repo_path / "package.json").is_file():
        return "npm"
    if (repo_path / "requirements.txt").is_file():
        return "pip-requirements"
    if (repo_path / "setup.py").is_file():
        return "pip-setup"
    return None


def _fetch_command(ecosystem: str, wheel_dir: Path) -> list[str]:
    """Phase 1 command — fetches dependencies WITH the network up.

    Runs no project lifecycle code (npm `--ignore-scripts`) / only downloads
    (pip), so this phase is deliberately NOT watched: a package manager
    fetching its declared dependencies from a registry is expected behaviour,
    not a signal. Doing the fetch here also means the watched phase never has
    to touch the network, so it can't hang retrying against the cutoff.
    """
    if ecosystem == "npm":
        return ["npm", "install", "--ignore-scripts"]
    if ecosystem == "pip-requirements":
        return ["pip3", "download", "-r", "requirements.txt", "-d", str(wheel_dir)]
    if ecosystem == "pip-setup":
        return ["pip3", "download", ".", "-d", str(wheel_dir)]
    raise ValueError(f"unknown ecosystem: {ecosystem}")


def _exec_script_command(ecosystem: str, wheel_dir: Path) -> list[str]:
    """Phase 2 command — runs the code an install would execute, network CUT.

    This is the watched phase: with dependencies already on disk and the
    network cut, any external connection attempt is a genuine signal, because
    a lifecycle script (npm) or an sdist's setup.py (pip) has no legitimate
    reason to reach the network here.
    """
    if ecosystem == "npm":
        root_scripts = " && ".join(
            f"npm run {name} --if-present" for name in _NPM_ROOT_LIFECYCLE_SCRIPTS
        )
        return ["bash", "-c", f"npm rebuild && {root_scripts}"]
    target = (
        ["-r", "requirements.txt"] if ecosystem == "pip-requirements" else ["."]
    )
    return ["pip3", "install", "--no-index", "--find-links", str(wheel_dir), *target]


def _is_external_connect(line: str) -> bool:
    """Only genuine external destinations count as cutoff violations.

    The cutoff policy explicitly ACCEPTs loopback traffic, so connects to
    127.x/::1 (npm hammers the systemd-resolved DNS stub at 127.0.0.53) and
    local AF_UNIX sockets are allowed by design and must not be flagged.
    """
    if "connect(" not in line:
        return False
    if "AF_INET" not in line:  # also matches AF_INET6; excludes AF_UNIX etc.
        return False
    if 'inet_addr("127.' in line:
        return False
    if '"::1"' in line:
        return False
    # Port-0 UDP connects are node/glibc address-selection probes: they
    # transmit nothing and happen for every resolved address, so they are
    # noise, not communication attempts.
    if "htons(0)" in line:
        return False
    return True


def run_dynamic_step(
    repo_path: Path, timeout: float = 120.0, fetch_timeout: float = 300.0
) -> dict:
    ecosystem = detect_ecosystem(repo_path)
    if ecosystem is None:
        return {
            "attempted": False,
            "command": None,
            "exit_code": None,
            "timed_out": False,
            "network_connect_attempts": [],
        }

    wheel_dir = repo_path.parent / "wheels"

    # Phase 1 (network UP, unwatched): fetch dependencies. A package manager
    # reaching its registry for declared dependencies is expected, so we do
    # not watch it — watching it flagged every normal npm/pip project. This
    # is a plain network download whose duration scales with project size
    # (a large npm project can take minutes), so it gets its own generous
    # timeout, separate from the tight cap on the watched phase below.
    fetch_timed_out = False
    try:
        fetch_result = subprocess.run(
            _fetch_command(ecosystem, wheel_dir),
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=fetch_timeout,
        )
        fetch_exit_code = fetch_result.returncode
    except subprocess.TimeoutExpired:
        # Don't abort: run the watched phase on whatever dependencies did
        # land, so the analysis still produces a result instead of failing.
        fetch_timed_out = True
        fetch_exit_code = None

    # Phase 2 (network CUT, watched): run the lifecycle scripts / setup.py.
    network_result = cut_network()

    telemetry_path = repo_path.parent / "telemetry.log"
    wrapped_command = [
        "strace",
        # Filter syscalls in-kernel (seccomp-bpf) instead of stopping every
        # traced process on every syscall. Without this, tracing dozens of
        # forked node processes loads the single-CPU VM so heavily that it
        # barely responds to anything else.
        "--seccomp-bpf",
        "-f",
        "-e",
        "trace=connect",
        "-o",
        str(telemetry_path),
        *_exec_script_command(ecosystem, wheel_dir),
    ]

    proc = subprocess.Popen(
        wrapped_command,
        cwd=repo_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        proc.communicate(timeout=timeout)
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        # Kill the WHOLE process group, not just strace: strace's tracees
        # (npm/node and their forks) survive strace's own death and — with
        # the network already cut — keep retrying connections for many
        # minutes, which keeps this script's systemd unit alive long after
        # the analysis is over. start_new_session above made `proc` the
        # group leader, so this reaps every descendant at once.
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        exit_code = None
        timed_out = True

    connect_attempts = []
    if telemetry_path.is_file():
        for line in telemetry_path.read_text(errors="ignore").splitlines():
            if _is_external_connect(line):
                connect_attempts.append(line.strip()[:200])

    return {
        "attempted": True,
        "command": _exec_script_command(ecosystem, wheel_dir),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "fetch_exit_code": fetch_exit_code,
        "fetch_timed_out": fetch_timed_out,
        "network_cutoff_applied": network_result["applied"],
        "network_connect_attempts": connect_attempts,
    }


def main() -> None:
    run(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
