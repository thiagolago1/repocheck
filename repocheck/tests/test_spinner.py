import io
import threading

from repocheck.spinner import Spinner


class _FakeTTYStream(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_update_writes_plain_line_when_not_interactive():
    stream = io.StringIO()  # StringIO.isatty() is False
    spinner = Spinner(stream=stream)

    spinner.update("Doing a thing")

    assert "Doing a thing" in stream.getvalue()


def test_non_interactive_never_starts_a_background_thread():
    stream = io.StringIO()
    threads_before = threading.active_count()

    with Spinner(stream=stream) as spinner:
        spinner.update("Doing a thing")
        assert threading.active_count() == threads_before

    assert threading.active_count() == threads_before


def test_interactive_starts_and_stops_a_background_thread():
    stream = _FakeTTYStream()
    threads_before = threading.active_count()

    with Spinner(stream=stream) as spinner:
        spinner.update("Doing a thing")
        assert threading.active_count() == threads_before + 1

    assert threading.active_count() == threads_before


def test_interactive_update_changes_displayed_message():
    stream = _FakeTTYStream()

    with Spinner(stream=stream) as spinner:
        spinner.update("First step")
        assert spinner._message == "First step"
        spinner.update("Second step")
        assert spinner._message == "Second step"
