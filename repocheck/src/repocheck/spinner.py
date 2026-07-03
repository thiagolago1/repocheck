import itertools
import shutil
import sys
import threading
import time
from typing import TextIO

_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_INTERVAL_SECONDS = 0.08


class Spinner:
    """A minimal animated terminal spinner for long-running CLI steps.

    Falls back to plain, non-animated status lines when `stream` isn't an
    interactive terminal (piped/redirected output, CI, etc.), so logs stay
    clean instead of filling up with carriage-return spinner frames.
    """

    def __init__(self, stream: TextIO = sys.stderr):
        self._stream = stream
        self._interactive = hasattr(stream, "isatty") and stream.isatty()
        self._message = ""
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def update(self, message: str) -> None:
        self._message = message
        if not self._interactive:
            self._stream.write(f"{message}\n")
            self._stream.flush()

    def _clear_line(self) -> None:
        width = shutil.get_terminal_size(fallback=(80, 20)).columns
        self._stream.write("\r" + " " * width + "\r")

    def _spin(self) -> None:
        for frame in itertools.cycle(_FRAMES):
            if self._stop_event.is_set():
                break
            self._clear_line()
            self._stream.write(f"{frame} {self._message}")
            self._stream.flush()
            time.sleep(_INTERVAL_SECONDS)
        self._clear_line()
        self._stream.flush()

    def __enter__(self) -> "Spinner":
        if self._interactive:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        return False
