"""Smoke tests for package imports and CLI entrypoint."""

from __future__ import annotations

import subprocess
import sys


class TestImports:
    def test_import_package(self) -> None:
        import credwolf

        assert hasattr(credwolf, "__version__")
        assert credwolf.__version__ == "1.0.0"

    def test_import_cli(self) -> None:
        from credwolf.cli import main

        assert callable(main)

    def test_import_models(self) -> None:
        from credwolf.models import AttackOptions, AuthResult, Protocol

        assert AuthResult is not None
        assert AttackOptions is not None
        assert Protocol is not None

    def test_import_log(self) -> None:
        from credwolf.log import Logger

        logger = Logger(verbosity=0)
        # Should not raise.
        logger.info("test")
        logger.debug("test")
        logger.verbose("test")


class TestCLISmoke:
    def test_help_flag(self) -> None:
        """``credwolf --help`` should exit 0."""
        result = subprocess.run(
            [sys.executable, "-m", "credwolf", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "Active Directory" in result.stdout

    def test_version_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "credwolf", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "1.0.0" in result.stdout

    def test_no_args_exits_nonzero(self) -> None:
        """Running with no arguments should fail (missing required --domain)."""
        result = subprocess.run(
            [sys.executable, "-m", "credwolf"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2

    def test_ntlm_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "credwolf", "-d", "x", "ntlm", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "--dc-ip" in result.stdout

    def test_kerberos_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "credwolf", "-d", "x", "kerberos", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "--kdc-ip" in result.stdout

    def test_ntlm_help_includes_hash(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "credwolf", "-d", "x", "ntlm", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "--hash" in result.stdout

    def test_kerberos_help_includes_inline_keys(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "credwolf", "-d", "x", "kerberos", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "--rc4-key" in result.stdout
        assert "--aes128-key" in result.stdout
        assert "--aes256-key" in result.stdout
