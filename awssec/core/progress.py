"""A transient one-line progress indicator on stderr.

Long scans (every region x every service, plus per-bucket / per-function
API calls) can run for minutes with no output, which looks hung. This
gives the user a live "where are we" line without polluting the report:

* It writes to **stderr**, so stdout stays clean for the console report
  and for ``--json > findings.json`` piping.
* It overwrites itself with carriage returns rather than scrolling.
* When stderr is not an interactive terminal (CI, redirection), it is
  silent -- logs don't fill with progress noise and behavior matches
  the pre-progress output exactly.

Modules receive a ``Progress`` via ``ScanContext.progress`` (a disabled
one by default, so they can call ``update()`` unconditionally); the CLI
swaps in an auto-detecting one for real runs.
"""

from __future__ import annotations

import shutil
import sys


class Progress:
    """One updatable status line on stderr (silent when not a TTY)."""

    def __init__(self, enabled: bool | None = None, stream=None):
        self.stream = stream if stream is not None else sys.stderr
        # None = auto-detect: only show progress on an interactive terminal.
        if enabled is None:
            enabled = bool(getattr(self.stream, "isatty", lambda: False)())
        self.enabled = enabled
        self._last_len = 0  # visible length of the line currently shown

    def update(self, message: str) -> None:
        """Show ``message``, replacing whatever status line is shown now."""
        if not self.enabled:
            return
        # Truncate to the terminal width: a wrapped line can't be overwritten
        # by a carriage return, which would corrupt the display.
        width = shutil.get_terminal_size((80, 24)).columns
        message = message[: max(width - 1, 1)]
        # Pad with spaces so a shorter message fully covers the previous one.
        pad = " " * max(self._last_len - len(message), 0)
        self.stream.write("\r" + message + pad)
        self.stream.flush()
        self._last_len = len(message)

    def clear(self) -> None:
        """Erase the status line (call before printing the real report)."""
        if not self.enabled or not self._last_len:
            return
        self.stream.write("\r" + " " * self._last_len + "\r")
        self.stream.flush()
        self._last_len = 0
