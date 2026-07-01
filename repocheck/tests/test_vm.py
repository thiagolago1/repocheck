import subprocess
from unittest.mock import patch

from repocheck.vm import check_multipass_available


def test_returns_false_when_multipass_binary_not_found():
    with patch("repocheck.vm.shutil.which", return_value=None) as mock_which:
        assert check_multipass_available() is False
    mock_which.assert_called_once_with("multipass")


def test_returns_true_when_multipass_version_succeeds():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch("repocheck.vm.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            assert check_multipass_available() is True
    mock_run.assert_called_once_with(
        ["multipass", "version"], capture_output=True, text=True, timeout=5
    )


def test_returns_false_when_multipass_version_fails():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch("repocheck.vm.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            assert check_multipass_available() is False


def test_returns_false_when_version_check_times_out():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch(
            "repocheck.vm.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="multipass version", timeout=5),
        ):
            assert check_multipass_available() is False


def test_returns_false_when_version_check_raises_os_error():
    with patch("repocheck.vm.shutil.which", return_value="/usr/local/bin/multipass"):
        with patch("repocheck.vm.subprocess.run", side_effect=OSError("boom")):
            assert check_multipass_available() is False
