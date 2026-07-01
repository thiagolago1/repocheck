import re
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
