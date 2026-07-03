import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from repocheck.vm import VMCleanupError, VMCommandTimeout, VMLaunchError, VMTransferError


def _make_mock_vm(bootstrap_rc=0, clone_rc=0, analyze_rc=0, report_payload=None):
    vm = MagicMock()
    vm.__enter__.return_value = vm
    vm.__exit__.return_value = False

    def run_side_effect(command, timeout=None):
        result = MagicMock()
        if command[:2] == ["bash", "-c"]:
            result.returncode = bootstrap_rc
            result.stderr = "" if bootstrap_rc == 0 else "bootstrap error"
        elif command[:2] == ["git", "clone"]:
            result.returncode = clone_rc
            result.stderr = "" if clone_rc == 0 else "clone error"
        else:
            result.returncode = analyze_rc
            result.stderr = "" if analyze_rc == 0 else "analyze error"
        return result

    vm.run.side_effect = run_side_effect

    payload = (
        report_payload
        if report_payload is not None
        else {"malicious_patterns": [], "git_findings": [], "secrets": []}
    )

    def pull_file_side_effect(remote_path, local_path):
        Path(local_path).write_text(json.dumps(payload))

    vm.pull_file.side_effect = pull_file_side_effect
    return vm


def test_run_static_analysis_happy_path():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(
        report_payload={
            "malicious_patterns": [
                {
                    "rule": "curl_pipe_shell",
                    "file": "install.sh",
                    "line": 3,
                    "snippet": "curl x | bash",
                }
            ],
            "git_findings": [],
            "secrets": [],
        }
    )
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert report.error is None
    assert len(report.malicious_patterns) == 1
    assert report.malicious_patterns[0]["rule"] == "curl_pipe_shell"
    mock_vm.push_file.assert_called_once()
    mock_vm.pull_file.assert_called_once()


def test_run_static_analysis_bootstrap_failure():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(bootstrap_rc=1)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is False
    assert "bootstrap failed" in report.error
    mock_vm.push_file.assert_not_called()


def test_run_static_analysis_clone_failure():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(clone_rc=128)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/nonexistent")

    assert report.clone_succeeded is False
    assert "clone failed" in report.error


def test_run_static_analysis_script_failure():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(analyze_rc=1)
    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "analysis script failed" in report.error


def test_run_analysis_degrades_gracefully_on_vm_launch_error():
    from repocheck.analysis import run_analysis

    mock_vm = MagicMock()
    mock_vm.__enter__.side_effect = VMLaunchError("no images available")

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is False
    assert "failed to launch" in report.error


def test_run_analysis_degrades_gracefully_on_command_timeout():
    """Regression test: a VMCommandTimeout (e.g. the analyze step or a real
    npm install taking longer than the timeout) must never propagate as an
    uncaught exception — it must degrade to a SUSPICIOUS-worthy report."""
    from repocheck.analysis import run_analysis

    def _success():
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        return result

    mock_vm = _make_mock_vm()
    mock_vm.run.side_effect = [
        _success(),  # bootstrap succeeds
        _success(),  # clone succeeds
        VMCommandTimeout("command timed out after 600.0s inside VM"),  # analyze step
    ]

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "did not finish within the" in report.error
    assert "timeout" in report.error


def test_run_analysis_degrades_gracefully_on_transfer_error():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm()
    mock_vm.push_file.side_effect = VMTransferError("failed to push analyze.py")

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "failed to transfer files" in report.error


def test_run_analysis_degrades_gracefully_on_cleanup_error():
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm()
    mock_vm.__exit__.side_effect = VMCleanupError("failed to destroy VM after retry")

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "failed to destroy the analysis VM" in report.error
