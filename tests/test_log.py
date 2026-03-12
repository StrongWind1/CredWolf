"""Tests for the Logger class."""

from __future__ import annotations

from credwolf.log import Logger


class TestLogger:
    def test_debug_requires_vv(self) -> None:
        logger_v1 = Logger(verbosity=1)
        logger_v2 = Logger(verbosity=2)
        # verbosity=1 should not print debug
        logger_v1.debug("should not appear")
        # verbosity=2 should — we just verify no exception
        logger_v2.debug("debug message")

    def test_verbose_requires_v(self) -> None:
        logger = Logger(verbosity=0)
        # Should not raise.
        logger.verbose("this should be silently ignored")

    def test_info_always_prints(self) -> None:
        logger = Logger(verbosity=0)
        # Should not raise.
        logger.info("info message")
        logger.success("success message")
        logger.warning("warning message")
        logger.error("error message")

    def test_lazy_formatting(self) -> None:
        logger = Logger(verbosity=2)
        logger.debug("user=%s domain=%s", "admin", "corp.local")
        logger.info("count=%d", 42)

    def test_format_skipped_when_silent(self) -> None:
        logger = Logger(verbosity=0)
        # If formatting were attempted with wrong args, it would crash.
        # But since verbosity=0 < DEBUG=2, _fmt is never called.
        logger.debug("message with %s placeholder")

    def test_error_with_formatting(self) -> None:
        logger = Logger(verbosity=0)
        logger.error("file %s not found on line %d", "/etc/hosts", 42)
