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


import warnings

import pytest

from repocheck.vm import (
    DEFAULT_IMAGE,
    EphemeralVM,
    MultipassNotAvailable,
    VMCleanupError,
    VMLaunchError,
)


def _mock_completed(returncode=0, stdout="", stderr=""):
    result = subprocess.CompletedProcess(args=[], returncode=returncode)
    result.stdout = stdout
    result.stderr = stderr
    return result


def test_enter_raises_when_multipass_unavailable():
    with patch("repocheck.vm.check_multipass_available", return_value=False):
        with patch("repocheck.vm.subprocess.run") as mock_run:
            with pytest.raises(MultipassNotAvailable):
                with EphemeralVM():
                    pass
    mock_run.assert_not_called()


def test_enter_launches_vm_with_correct_command():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run", return_value=_mock_completed(returncode=0)
        ) as mock_run:
            with EphemeralVM(image="24.04", launch_timeout=60.0) as vm:
                launch_name = vm.name

    launch_call = mock_run.call_args_list[0]
    assert launch_call.args[0] == [
        "multipass", "launch", "24.04", "--name", launch_name,
        "--timeout", "60",
    ]
    assert launch_call.kwargs["timeout"] == 90.0


def test_enter_raises_vm_launch_error_on_nonzero_exit():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run",
            return_value=_mock_completed(returncode=1, stderr="no images available"),
        ):
            with pytest.raises(VMLaunchError, match="no images available"):
                with EphemeralVM():
                    pass


def test_exit_always_calls_delete_with_purge():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run", return_value=_mock_completed(returncode=0)
        ) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name

    delete_call = mock_run.call_args_list[-1]
    assert delete_call.args[0] == ["multipass", "delete", name, "--purge"]


def test_exit_destroys_vm_even_when_block_raises():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run", return_value=_mock_completed(returncode=0)
        ) as mock_run:
            with pytest.raises(RuntimeError, match="boom"):
                with EphemeralVM() as vm:
                    name = vm.name
                    raise RuntimeError("boom")

    delete_call = mock_run.call_args_list[-1]
    assert delete_call.args[0] == ["multipass", "delete", name, "--purge"]


def test_exit_retries_delete_once_on_failure():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            _mock_completed(returncode=1, stderr="busy"),  # delete attempt 1
            _mock_completed(returncode=0),   # delete attempt 2 (retry succeeds)
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM():
                pass

    assert mock_run.call_count == 3


def test_exit_raises_cleanup_error_when_delete_fails_twice_and_no_other_exception():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            _mock_completed(returncode=1, stderr="busy"),  # delete attempt 1
            _mock_completed(returncode=1, stderr="still busy"),  # delete attempt 2
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with pytest.raises(VMCleanupError, match="still busy"):
                with EphemeralVM():
                    pass


def test_exit_warns_instead_of_masking_original_exception():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            _mock_completed(returncode=1, stderr="busy"),  # delete attempt 1
            _mock_completed(returncode=1, stderr="still busy"),  # delete attempt 2
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with pytest.warns(RuntimeWarning, match="still busy"):
                with pytest.raises(RuntimeError, match="original error"):
                    with EphemeralVM():
                        raise RuntimeError("original error")


def test_enter_raises_vm_launch_error_when_subprocess_times_out():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        with patch(
            "repocheck.vm.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="multipass launch", timeout=150.0),
        ):
            with pytest.raises(VMLaunchError):
                with EphemeralVM():
                    pass


def test_exit_retries_and_raises_cleanup_error_when_delete_raises_os_error_twice():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            OSError("multipass daemon not responding"),  # delete attempt 1
            OSError("multipass daemon not responding"),  # delete attempt 2
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with pytest.raises(VMCleanupError, match="multipass daemon not responding"):
                with EphemeralVM():
                    pass


def test_exit_warns_instead_of_raising_when_delete_raises_and_exception_already_propagating():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),   # launch
            OSError("multipass daemon not responding"),  # delete attempt 1
            OSError("multipass daemon not responding"),  # delete attempt 2
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with pytest.warns(RuntimeWarning):
                with pytest.raises(RuntimeError, match="original error"):
                    with EphemeralVM():
                        raise RuntimeError("original error")


from repocheck.vm import VMCommandResult, VMCommandTimeout


def test_run_executes_command_and_returns_result():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0, stdout="hello\n", stderr=""),  # run
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name
                result = vm.run(["echo", "hello"], timeout=10.0)

    assert result == VMCommandResult(returncode=0, stdout="hello\n", stderr="")
    run_call = mock_run.call_args_list[1]
    assert run_call.args[0] == ["multipass", "exec", name, "--", "echo", "hello"]
    assert run_call.kwargs["timeout"] == 10.0


def test_run_raises_vm_command_timeout_on_subprocess_timeout():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0),  # delete (runs after the nested patch below reverts)
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with EphemeralVM() as vm:
                with patch(
                    "repocheck.vm.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="multipass exec", timeout=10.0),
                ):
                    with pytest.raises(VMCommandTimeout):
                        vm.run(["sleep", "999"], timeout=10.0)


from pathlib import Path

from repocheck.vm import VMTransferError


def test_push_file_calls_multipass_transfer_with_correct_args():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0),  # transfer
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name
                vm.push_file(Path("/tmp/analyze.py"), "/home/ubuntu/analyze.py")

    transfer_call = mock_run.call_args_list[1]
    assert transfer_call.args[0] == [
        "multipass", "transfer", "/tmp/analyze.py", f"{name}:/home/ubuntu/analyze.py",
    ]


def test_push_file_raises_vm_transfer_error_on_failure():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=1, stderr="no such file"),  # transfer
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with EphemeralVM() as vm:
                with pytest.raises(VMTransferError, match="no such file"):
                    vm.push_file(Path("/tmp/missing.py"), "/home/ubuntu/missing.py")


def test_pull_file_calls_multipass_transfer_with_correct_args():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=0),  # transfer
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses) as mock_run:
            with EphemeralVM() as vm:
                name = vm.name
                vm.pull_file("/home/ubuntu/report.json", Path("/tmp/report.json"))

    transfer_call = mock_run.call_args_list[1]
    assert transfer_call.args[0] == [
        "multipass", "transfer", f"{name}:/home/ubuntu/report.json", "/tmp/report.json",
    ]


def test_pull_file_raises_vm_transfer_error_on_failure():
    with patch("repocheck.vm.check_multipass_available", return_value=True):
        responses = [
            _mock_completed(returncode=0),  # launch
            _mock_completed(returncode=1, stderr="permission denied"),  # transfer
            _mock_completed(returncode=0),  # delete
        ]
        with patch("repocheck.vm.subprocess.run", side_effect=responses):
            with EphemeralVM() as vm:
                with pytest.raises(VMTransferError, match="permission denied"):
                    vm.pull_file("/home/ubuntu/report.json", Path("/tmp/report.json"))
