"""Structured console logger using ANSI escape codes."""

from __future__ import annotations

import sys

# Verbosity thresholds.
VERBOSE = 1
DEBUG = 2

# ANSI color codes.  Colors are only emitted when stderr is a terminal.
_IS_TTY = sys.stderr.isatty()


def _ansi(code: str, text: str) -> str:
    if _IS_TTY:
        return f"\033[{code}m{text}\033[0m"
    return text


# Prefix strings with optional color.
_PREFIX_DEBUG = _ansi("33", "[DEBUG]")  # yellow
_PREFIX_VERBOSE = _ansi("34", "[VERBOSE]")  # blue
_PREFIX_INFO = _ansi("1;34", "[*]")  # bold blue
_PREFIX_SUCCESS = _ansi("1;32", "[+]")  # bold green
_PREFIX_WARNING = _ansi("1;33", "[-]")  # bold yellow/orange
_PREFIX_ERROR = _ansi("1;31", "[!]")  # bold red


class Logger:
    """Simple levelled logger that writes to stderr.

    Supports lazy ``%``-style formatting: the format string is only
    interpolated when the message will actually be emitted.

    Usage::

        logger.debug("user=%s domain=%s", user, domain)
    """

    def __init__(self, verbosity: int = 0) -> None:
        """Create a logger with the given verbosity level."""
        self.verbosity = verbosity

    @staticmethod
    def _fmt(message: str, args: tuple[object, ...]) -> str:
        return message % args if args else message

    @staticmethod
    def _emit(prefix: str, message: str) -> None:
        print(f"{prefix} {message}", file=sys.stderr)

    # -- public helpers -----------------------------------------------------

    def debug(self, message: str, *args: object) -> None:
        """Emit a message only at debug verbosity (``-vv``)."""
        if self.verbosity >= DEBUG:
            self._emit(_PREFIX_DEBUG, self._fmt(message, args))

    def verbose(self, message: str, *args: object) -> None:
        """Emit a message at verbose or higher (``-v``)."""
        if self.verbosity >= VERBOSE:
            self._emit(_PREFIX_VERBOSE, self._fmt(message, args))

    def info(self, message: str, *args: object) -> None:
        """Emit an informational message (always shown)."""
        self._emit(_PREFIX_INFO, self._fmt(message, args))

    def success(self, message: str, *args: object) -> None:
        """Emit a success message (always shown)."""
        self._emit(_PREFIX_SUCCESS, self._fmt(message, args))

    def warning(self, message: str, *args: object) -> None:
        """Emit a warning message (always shown)."""
        self._emit(_PREFIX_WARNING, self._fmt(message, args))

    def error(self, message: str, *args: object) -> None:
        """Emit an error message (always shown)."""
        self._emit(_PREFIX_ERROR, self._fmt(message, args))
