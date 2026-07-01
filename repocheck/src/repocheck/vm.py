import shutil
import subprocess


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
