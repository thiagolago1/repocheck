from pathlib import Path

import pytest

from repocheck.vm import EphemeralVM, check_multipass_available

pytestmark = pytest.mark.skipif(
    not check_multipass_available(),
    reason="multipass CLI not installed/available in this environment",
)


def test_full_lifecycle_launch_run_transfer_destroy(tmp_path):
    local_input = tmp_path / "input.txt"
    local_input.write_text("hello from host\n")
    local_output = tmp_path / "output.txt"

    with EphemeralVM(launch_timeout=180.0) as vm:
        vm_name = vm.name

        vm.push_file(local_input, "/home/ubuntu/input.txt")

        result = vm.run(["cat", "/home/ubuntu/input.txt"], timeout=30.0)
        assert result.returncode == 0
        assert result.stdout == "hello from host\n"

        vm.run(
            ["cp", "/home/ubuntu/input.txt", "/home/ubuntu/output.txt"], timeout=30.0
        )
        vm.pull_file("/home/ubuntu/output.txt", local_output)

    assert local_output.read_text() == "hello from host\n"

    # Confirm the VM is really gone after the context manager exits.
    import subprocess

    list_result = subprocess.run(
        ["multipass", "list", "--format", "csv"], capture_output=True, text=True, timeout=30
    )
    assert vm_name not in list_result.stdout
