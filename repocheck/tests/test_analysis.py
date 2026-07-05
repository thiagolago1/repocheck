import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from repocheck.vm import VMCleanupError, VMCommandTimeout, VMLaunchError, VMTransferError


def _make_mock_vm(bootstrap_rc=0, clone_rc=0, analyze_rc=0, report_payload=None):
    """Mock VM speaking the detached-analysis protocol.

    The analysis script is launched as a detached systemd unit (so the exec
    channel never has to survive the in-VM network cutoff), then the host
    polls the unit state with short fresh exec calls and finally checks for
    the report file. `analyze_rc` simulates the script's outcome via that
    report-file check: 0 = report written, nonzero = script died before
    writing it (its log is then read for the error message).
    """
    vm = MagicMock()
    vm.__enter__.return_value = vm
    vm.__exit__.return_value = False

    def run_side_effect(command, timeout=None):
        result = MagicMock()
        result.stdout = ""
        result.stderr = ""
        if command[:2] == ["bash", "-c"]:
            result.returncode = bootstrap_rc
            result.stderr = "" if bootstrap_rc == 0 else "bootstrap error"
        elif command[:2] == ["git", "clone"]:
            result.returncode = clone_rc
            result.stderr = "" if clone_rc == 0 else "clone error"
        elif command[:2] == ["sudo", "systemd-run"]:
            result.returncode = 0
        elif command[:2] == ["systemctl", "is-active"]:
            result.returncode = 3
            result.stdout = "inactive\n"
        elif command[:2] == ["test", "-f"]:
            result.returncode = analyze_rc
        elif command[0] == "cat":
            result.returncode = 0
            result.stdout = "analyze error"
        else:
            result.returncode = 0
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
    """Regression test: a VMCommandTimeout on any individual exec call must
    never propagate as an uncaught exception — it must degrade to a
    SUSPICIOUS-worthy report."""
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
        VMCommandTimeout("command timed out after 60.0s inside VM"),  # launch call
    ]

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.clone_succeeded is True
    assert "did not finish within the" in report.error
    assert "timeout" in report.error


def test_poll_timeout_is_treated_as_still_running_not_failure():
    """Regression test (observed live): while npm install runs under strace
    inside the single-CPU VM, the VM can get so loaded that an individual
    poll exceeds its own command timeout. That must mean 'busy, still
    running' — poll again until the overall deadline — not abort the whole
    analysis."""
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm()
    original_side_effect = mock_vm.run.side_effect
    poll_calls = {"count": 0}

    def flaky_polls(command, timeout=None):
        if command[:2] == ["test", "-f"]:
            poll_calls["count"] += 1
            if poll_calls["count"] <= 2:
                raise VMCommandTimeout("command timed out after 60.0s inside VM")
        return original_side_effect(command, timeout=timeout)

    mock_vm.run.side_effect = flaky_polls

    with patch("repocheck.analysis.time.sleep"):
        with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
            report = run_analysis("https://github.com/example/repo")

    assert report.error is None
    assert report.clone_succeeded is True
    assert poll_calls["count"] == 3
    mock_vm.pull_file.assert_called_once()


def test_report_file_is_the_completion_signal_even_if_unit_stays_active():
    """Regression test (observed live): strace's tracees (npm/node) can
    outlive the dynamic step's timeout and keep the systemd unit 'active'
    for many extra minutes after analyze.py has already written the report.
    The report file's existence — not the unit state — is the completion
    signal, so results must be collected as soon as it appears."""
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm()
    original_side_effect = mock_vm.run.side_effect

    def unit_never_ends(command, timeout=None):
        result = original_side_effect(command, timeout=timeout)
        if command[:2] == ["systemctl", "is-active"]:
            result.returncode = 0
            result.stdout = "active\n"
        return result

    mock_vm.run.side_effect = unit_never_ends

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo")

    assert report.error is None
    assert report.clone_succeeded is True
    mock_vm.pull_file.assert_called_once()


def test_run_analysis_degrades_gracefully_when_analysis_never_finishes():
    """If the unit stays active and no report ever appears before the
    deadline, the result must be a graceful timeout report — not a hang and
    not a crash."""
    from repocheck.analysis import run_analysis

    mock_vm = _make_mock_vm(analyze_rc=1)
    original_side_effect = mock_vm.run.side_effect

    def always_active(command, timeout=None):
        result = original_side_effect(command, timeout=timeout)
        if command[:2] == ["systemctl", "is-active"]:
            result.returncode = 0
            result.stdout = "active\n"
        return result

    mock_vm.run.side_effect = always_active

    with patch("repocheck.analysis.EphemeralVM", return_value=mock_vm):
        report = run_analysis("https://github.com/example/repo", timeout=0.0)

    assert report.clone_succeeded is True
    assert "did not finish within the" in report.error
    mock_vm.pull_file.assert_not_called()


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
