import shutil
import subprocess
import uuid
import warnings
from dataclasses import dataclass
from pathlib import Path


class MultipassNotAvailable(Exception):
    pass


def check_multipass_available() -> bool:
    if shutil.which("multipass") is None:
        return False
    try:
        result = subprocess.run(
            ["multipass", "version"], capture_output=True, text=True, timeout=5
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


class VMLaunchError(Exception):
    pass


class VMCleanupError(Exception):
    pass


@dataclass
class VMCommandResult:
    returncode: int
    stdout: str
    stderr: str


class VMCommandTimeout(Exception):
    pass


class VMTransferError(Exception):
    pass


DEFAULT_IMAGE = "24.04"


class EphemeralVM:
    def __init__(self, image: str = DEFAULT_IMAGE, launch_timeout: float = 120.0):
        self.image = image
        self.launch_timeout = launch_timeout
        self.name = f"repocheck-{uuid.uuid4().hex[:12]}"

    def __enter__(self) -> "EphemeralVM":
        if not check_multipass_available():
            raise MultipassNotAvailable(
                "multipass CLI not found or not working; install it to run "
                "the dynamic analysis stage"
            )
        try:
            result = subprocess.run(
                [
                    "multipass", "launch", self.image, "--name", self.name,
                    "--timeout", str(int(self.launch_timeout)),
                ],
                capture_output=True,
                text=True,
                timeout=self.launch_timeout + 30,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise VMLaunchError(
                f"failed to launch multipass VM '{self.name}': {exc}"
            ) from exc
        if result.returncode != 0:
            raise VMLaunchError(
                f"failed to launch multipass VM '{self.name}': {result.stderr.strip()}"
            )
        return self

    def _attempt_delete(self) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                ["multipass", "delete", self.name, "--purge"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return False, str(exc)
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, ""

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        success, _ = self._attempt_delete()
        if not success:
            retry_success, retry_message = self._attempt_delete()
            if not retry_success:
                message = (
                    f"failed to destroy VM '{self.name}' after retry; "
                    f"check manually with 'multipass list': {retry_message}"
                )
                if exc_type is None:
                    raise VMCleanupError(message)
                warnings.warn(message, RuntimeWarning, stacklevel=2)
        return False

    def run(self, command: list[str], timeout: float = 60.0) -> VMCommandResult:
        try:
            result = subprocess.run(
                ["multipass", "exec", self.name, "--", *command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise VMCommandTimeout(
                f"command timed out after {timeout}s inside VM '{self.name}': {command}"
            ) from exc
        return VMCommandResult(
            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
        )

    def push_file(self, local_path: Path, remote_path: str) -> None:
        try:
            result = subprocess.run(
                ["multipass", "transfer", str(local_path), f"{self.name}:{remote_path}"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise VMTransferError(
                f"failed to push {local_path} to VM '{self.name}:{remote_path}': {exc}"
            ) from exc
        if result.returncode != 0:
            raise VMTransferError(
                f"failed to push {local_path} to VM '{self.name}:{remote_path}': "
                f"{result.stderr.strip()}"
            )

    def pull_file(self, remote_path: str, local_path: Path) -> None:
        try:
            result = subprocess.run(
                ["multipass", "transfer", f"{self.name}:{remote_path}", str(local_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise VMTransferError(
                f"failed to pull VM '{self.name}:{remote_path}' to {local_path}: {exc}"
            ) from exc
        if result.returncode != 0:
            raise VMTransferError(
                f"failed to pull VM '{self.name}:{remote_path}' to {local_path}: "
                f"{result.stderr.strip()}"
            )
