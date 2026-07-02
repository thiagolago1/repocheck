import json
import re
import shutil
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
    }
    output_path.write_text(json.dumps(report, indent=2))


def main() -> None:
    run(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
