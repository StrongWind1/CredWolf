"""Tests for AttackRunner result handling, output, and control flow."""

from __future__ import annotations

import io
import os

import pytest

from credwolf.attack import AttackRunner
from credwolf.log import Logger
from credwolf.models import AttackOptions, AuthResult, Protocol


def _make_runner(
    protocol: Protocol = Protocol.NTLM,
    output_file: io.StringIO | None = None,
    **kwargs,
) -> AttackRunner:
    opts = AttackOptions(protocol=protocol, domain="corp.local", **kwargs)
    logger = Logger(verbosity=0)
    return AttackRunner(opts, logger, output_file)


# ======================================================================
# _handle_auth_results
# ======================================================================


class TestHandleAuthResults:
    def test_connection_failed_is_silent(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=False, details="connection failed"))
        assert buf.getvalue() == ""

    def test_success_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=True))
        assert buf.getvalue() == "corp.local/admin:Pass1@password\n"

    def test_success_no_output_file(self) -> None:
        runner = _make_runner()
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=True))

    def test_indeterminate_smb_status_not_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=None, details="STATUS_ACCOUNT_DISABLED"))
        assert buf.getvalue() == ""

    def test_response_too_big_does_not_set_clock_skew(self) -> None:
        runner = _make_runner(protocol=Protocol.KERBEROS)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=False, details="KRB_ERR_RESPONSE_TOO_BIG"))
        assert runner._clock_skew is False

    def test_response_too_big_not_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.KERBEROS, output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=False, details="KRB_ERR_RESPONSE_TOO_BIG"))
        assert buf.getvalue() == ""

    def test_clock_skew_sets_flag(self) -> None:
        runner = _make_runner(protocol=Protocol.KERBEROS)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=False, details="KRB_AP_ERR_SKEW"))
        assert runner._clock_skew is True

    def test_clock_skew_not_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.KERBEROS, output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=False, details="KRB_AP_ERR_SKEW"))
        assert buf.getvalue() == ""

    def test_revoked_account_not_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "", "password", AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED"))
        assert buf.getvalue() == ""

    def test_key_expired_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=True, details="KDC_ERR_KEY_EXPIRED"))
        assert buf.getvalue() == "corp.local/admin:Pass1@password\n"

    def test_policy_indeterminate_not_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=None, details="KDC_ERR_POLICY"))
        assert buf.getvalue() == ""

    def test_plain_failure_silent(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "wrong", "password", AuthResult(success=False))
        assert buf.getvalue() == ""

    def test_multiple_successes_appended(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "Pass1", "password", AuthResult(success=True))
        runner._handle_auth_results("corp.local", "john", "Pass2", "password", AuthResult(success=True))
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 2
        assert lines[0] == "corp.local/admin:Pass1@password"
        assert lines[1] == "corp.local/john:Pass2@password"


# ======================================================================
# Output format: domain/user:secret@type
# ======================================================================


class TestCredentialFormat:
    def test_password_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("evil.corp", "Administrator", "Password1!", "password", AuthResult(success=True))
        assert buf.getvalue().strip() == "evil.corp/Administrator:Password1!@password"

    def test_hash_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("evil.corp", "admin", "7facdc498ed1680c4fd1448319a8c04f", "nt_hash", AuthResult(success=True))
        assert buf.getvalue().strip() == "evil.corp/admin:7facdc498ed1680c4fd1448319a8c04f@nt_hash"

    def test_rc4_key_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        key = "a" * 32
        runner._handle_auth_results("evil.corp", "admin", key, "rc4_key", AuthResult(success=True))
        assert buf.getvalue().strip() == f"evil.corp/admin:{key}@rc4_key"

    def test_aes128_key_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        key = "b" * 32
        runner._handle_auth_results("evil.corp", "admin", key, "aes128_key", AuthResult(success=True))
        assert buf.getvalue().strip() == f"evil.corp/admin:{key}@aes128_key"

    def test_aes256_key_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        key = "c" * 64
        runner._handle_auth_results("evil.corp", "admin", key, "aes256_key", AuthResult(success=True))
        assert buf.getvalue().strip() == f"evil.corp/admin:{key}@aes256_key"

    def test_empty_secret_omits_colon(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("evil.corp", "admin", "", "ccache", AuthResult(success=True))
        assert buf.getvalue().strip() == "evil.corp/admin@ccache"

    def test_ccache_ticket_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("evil.corp", "admin", "admin.ccache", "ccache", AuthResult(success=True))
        assert buf.getvalue().strip() == "evil.corp/admin:admin.ccache@ccache"

    def test_kirbi_ticket_format(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("evil.corp", "admin", "admin.kirbi", "kirbi", AuthResult(success=True))
        assert buf.getvalue().strip() == "evil.corp/admin:admin.kirbi@kirbi"


# ======================================================================
# _should_stop
# ======================================================================


class TestShouldStop:
    def test_normal_continues(self) -> None:
        runner = _make_runner()
        assert runner._should_stop(success=False) is False

    def test_none_continues(self) -> None:
        runner = _make_runner()
        assert runner._should_stop(success=None) is False

    def test_success_without_flag_continues(self) -> None:
        runner = _make_runner()
        assert runner._should_stop(success=True) is False

    def test_connection_failed_stops(self) -> None:
        runner = _make_runner()
        runner._connection_failed = True
        assert runner._should_stop(success=False) is True

    def test_connection_failed_stops_even_on_none(self) -> None:
        runner = _make_runner()
        runner._connection_failed = True
        assert runner._should_stop(success=None) is True

    def test_clock_skew_stops(self) -> None:
        runner = _make_runner()
        runner._clock_skew = True
        assert runner._should_stop(success=False) is True

    def test_clock_skew_stops_even_on_success(self) -> None:
        runner = _make_runner()
        runner._clock_skew = True
        assert runner._should_stop(success=True) is True

    def test_stop_on_success_with_success(self) -> None:
        runner = _make_runner(stop_on_success=True)
        assert runner._should_stop(success=True) is True

    def test_stop_on_success_with_failure(self) -> None:
        runner = _make_runner(stop_on_success=True)
        assert runner._should_stop(success=False) is False

    def test_stop_on_success_with_none(self) -> None:
        runner = _make_runner(stop_on_success=True)
        assert runner._should_stop(success=None) is False


# ======================================================================
# _write_output
# ======================================================================


class TestWriteOutput:
    def test_writes_line_with_newline(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._write_output("corp.local/admin:Pass1@password")
        assert buf.getvalue() == "corp.local/admin:Pass1@password\n"

    def test_multiple_writes(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._write_output("line1")
        runner._write_output("line2")
        assert buf.getvalue() == "line1\nline2\n"

    def test_no_file_is_noop(self) -> None:
        runner = _make_runner()
        runner._write_output("anything")


# ======================================================================
# _read_lines
# ======================================================================


class TestReadLines:
    def test_valid_file(self, tmp_path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("admin\njohn\njane\n")
        runner = _make_runner()
        lines = runner._read_lines(str(f))
        assert lines == ["admin", "john", "jane"]

    def test_file_without_trailing_newline(self, tmp_path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("admin\njohn")
        runner = _make_runner()
        lines = runner._read_lines(str(f))
        assert lines == ["admin", "john"]

    def test_file_not_found(self) -> None:
        runner = _make_runner()
        result = runner._read_lines("/nonexistent/path/file.txt")
        assert result is None

    def test_empty_file(self, tmp_path) -> None:
        f = tmp_path / "empty.txt"
        f.write_text("")
        runner = _make_runner()
        lines = runner._read_lines(str(f))
        assert lines == []

    def test_single_line(self, tmp_path) -> None:
        f = tmp_path / "one.txt"
        f.write_text("admin\n")
        runner = _make_runner()
        lines = runner._read_lines(str(f))
        assert lines == ["admin"]

    def test_whitespace_lines(self, tmp_path) -> None:
        f = tmp_path / "ws.txt"
        f.write_text("admin\n  \njohn\n")
        runner = _make_runner()
        lines = runner._read_lines(str(f))
        assert lines == ["admin", "  ", "john"]

    @pytest.mark.skipif(os.getuid() == 0, reason="root ignores file permissions")
    def test_permission_denied(self, tmp_path) -> None:
        f = tmp_path / "locked.txt"
        f.write_text("data")
        f.chmod(0o000)
        runner = _make_runner()
        result = runner._read_lines(str(f))
        assert result is None
        f.chmod(0o644)


# ======================================================================
# Integration: _attempt sets _connection_failed
# ======================================================================


class TestAttemptConnectionFailed:
    def test_connection_failed_flag_set(self) -> None:
        runner = _make_runner(dc_ip="192.0.2.1")
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=False, details="connection failed")
        runner._attempt("admin", secret_type="password", password="Pass1")
        assert runner._connection_failed is True

    def test_normal_failure_no_flag(self) -> None:
        runner = _make_runner(dc_ip="192.0.2.1")
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=False)
        runner._attempt("admin", secret_type="password", password="Pass1")
        assert runner._connection_failed is False


# ======================================================================
# Integration: output file via run()
# ======================================================================


class TestRunWithOutputFile:
    def test_password_success_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", user="admin", password="Pass1", output_file=buf)
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=True)
        runner.run()
        assert "corp.local/admin:Pass1@password" in buf.getvalue()

    def test_hash_success_written(self, tmp_path) -> None:
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("aabbccdd11223344aabbccdd11223344\n")
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", user="admin", hashes_file=str(hash_file), output_file=buf)
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=True)
        runner.run()
        assert "@nt_hash" in buf.getvalue()

    def test_failure_not_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", user="admin", password="wrong", output_file=buf)
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=False)
        runner.run()
        assert buf.getvalue() == ""

    def test_colon_file_password(self, tmp_path) -> None:
        creds = tmp_path / "creds.txt"
        creds.write_text("admin:Pass1\njohn:Pass2\n")
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", user_pass_file=str(creds), output_file=buf)
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=True)
        runner.run()
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 2
        assert "corp.local/admin:Pass1@password" in lines[0]
        assert "corp.local/john:Pass2@password" in lines[1]

    def test_colon_file_hash(self, tmp_path) -> None:
        creds = tmp_path / "creds.txt"
        creds.write_text("admin:aabbccdd11223344aabbccdd11223344\n")
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", user_hash_file=str(creds), output_file=buf)
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=True)
        runner.run()
        assert "@nt_hash" in buf.getvalue()

    def test_stop_on_success_halts(self, tmp_path) -> None:
        passwords = tmp_path / "pass.txt"
        passwords.write_text("wrong1\nright\nwrong2\n")
        call_count = 0

        def mock_test(**_kw):
            nonlocal call_count
            call_count += 1
            return AuthResult(success=(call_count == 2))

        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", user="admin", passwords_file=str(passwords), stop_on_success=True, output_file=buf)
        runner.ntlm.test_credentials = mock_test
        runner.run()
        assert call_count == 2
        assert buf.getvalue().strip() == "corp.local/admin:right@password"

    def test_users_file_iteration(self, tmp_path) -> None:
        users = tmp_path / "users.txt"
        users.write_text("admin\njohn\n")
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", users_file=str(users), password="Pass1", output_file=buf)
        runner.ntlm.test_credentials = lambda **_kw: AuthResult(success=True)
        runner.run()
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 2

    def test_empty_users_file(self, tmp_path) -> None:
        users = tmp_path / "users.txt"
        users.write_text("\n  \n")
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", users_file=str(users), password="Pass1", output_file=buf)
        runner.run()
        assert buf.getvalue() == ""

    def test_missing_file(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(dc_ip="192.0.2.1", users_file="/nonexistent/users.txt", password="Pass1", output_file=buf)
        runner.run()
        assert buf.getvalue() == ""


# ======================================================================
# Clock skew stops iteration
# ======================================================================


class TestClockSkewStopsIteration:
    def test_clock_skew_stops_password_iteration(self, tmp_path) -> None:
        passwords = tmp_path / "pass.txt"
        passwords.write_text("pass1\npass2\npass3\n")
        call_count = 0

        def mock_test(**_kw):
            nonlocal call_count
            call_count += 1
            return AuthResult(success=False, details="KRB_AP_ERR_SKEW")

        runner = _make_runner(protocol=Protocol.KERBEROS, kdc_ip="10.0.0.1", user="admin", passwords_file=str(passwords))
        runner.kerberos.pre_authentication = lambda **_kw: AuthResult(success=False, details="KRB_AP_ERR_SKEW")
        runner.run()
        assert runner._clock_skew is True


# ======================================================================
# Revoked account handling (disabled / expired / locked out)
# ======================================================================


class TestRevokedAccountHandling:
    def test_revoked_account_not_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(output_file=buf)
        runner._handle_auth_results("corp.local", "admin", "", "password", AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED"))
        assert buf.getvalue() == ""

    def test_revoked_increments_consecutive_counter(self) -> None:
        runner = _make_runner()
        runner._handle_auth_results("corp.local", "user1", "", "password", AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED"))
        assert runner._consecutive_revoked == 1
        runner._handle_auth_results("corp.local", "user2", "", "password", AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED"))
        assert runner._consecutive_revoked == 2

    def test_non_revoked_resets_consecutive_counter(self) -> None:
        runner = _make_runner()
        runner._handle_auth_results("corp.local", "user1", "", "password", AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED"))
        assert runner._consecutive_revoked == 1
        runner._handle_auth_results("corp.local", "user2", "Pass1", "password", AuthResult(success=False))
        assert runner._consecutive_revoked == 0

    def test_success_resets_consecutive_counter(self) -> None:
        runner = _make_runner()
        runner._handle_auth_results("corp.local", "user1", "", "password", AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED"))
        runner._handle_auth_results("corp.local", "user2", "Pass1", "password", AuthResult(success=True))
        assert runner._consecutive_revoked == 0


# ======================================================================
# --max-lockouts stops iteration
# ======================================================================


class TestMaxLockoutsStopsIteration:
    def test_max_lockouts_stops_after_threshold(self, tmp_path) -> None:
        users = tmp_path / "users.txt"
        users.write_text("user1\nuser2\nuser3\nuser4\nuser5\n")
        call_count = 0

        def mock_test(**_kw):
            nonlocal call_count
            call_count += 1
            return AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED")

        runner = _make_runner(protocol=Protocol.KERBEROS, kdc_ip="10.0.0.1", users_file=str(users), password="Pass1", max_lockouts=3)
        runner.kerberos.pre_authentication = mock_test
        runner.run()
        assert call_count == 3
        assert runner._consecutive_revoked == 3

    def test_max_lockouts_resets_on_success(self, tmp_path) -> None:
        users = tmp_path / "users.txt"
        users.write_text("user1\nuser2\nuser3\nuser4\nuser5\n")
        call_count = 0

        def mock_test(**_kw):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return AuthResult(success=True)
            return AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED")

        runner = _make_runner(protocol=Protocol.KERBEROS, kdc_ip="10.0.0.1", users_file=str(users), password="Pass1", max_lockouts=3)
        runner.kerberos.pre_authentication = mock_test
        runner.run()
        # user1=revoked(1), user2=success(reset to 0), user3=revoked(1), user4=revoked(2), user5=revoked(3→stop)
        assert call_count == 5

    def test_max_lockouts_zero_disables(self, tmp_path) -> None:
        users = tmp_path / "users.txt"
        users.write_text("user1\nuser2\nuser3\n")

        runner = _make_runner(protocol=Protocol.KERBEROS, kdc_ip="10.0.0.1", users_file=str(users), password="Pass1", max_lockouts=0)
        runner.kerberos.pre_authentication = lambda **_kw: AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED")
        runner.run()
        # All 3 should be attempted (max_lockouts=0 means disabled)
        assert runner._consecutive_revoked == 3

    def test_should_stop_with_max_lockouts(self) -> None:
        runner = _make_runner(max_lockouts=2)
        runner._consecutive_revoked = 2
        assert runner._should_stop(success=False) is True

    def test_should_stop_below_max_lockouts(self) -> None:
        runner = _make_runner(max_lockouts=3)
        runner._consecutive_revoked = 2
        assert runner._should_stop(success=False) is False


# ======================================================================
# Timeout propagation
# ======================================================================

# ======================================================================
# Username enumeration
# ======================================================================


class TestUserenumRun:
    def test_valid_users_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", user="Administrator", output_file=buf)
        runner.kerberos.enumerate_user = lambda *_a, **_kw: AuthResult(success=True)
        runner.run()
        assert "corp.local/Administrator" in buf.getvalue()

    def test_asreproastable_users_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", user="svc_backup", output_file=buf)
        runner.kerberos.enumerate_user = lambda *_a, **_kw: AuthResult(success=True, details="no_preauth")
        runner.run()
        assert "corp.local/svc_backup" in buf.getvalue()

    def test_revoked_users_written_to_output(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", user="Guest", output_file=buf)
        runner.kerberos.enumerate_user = lambda *_a, **_kw: AuthResult(success=True, details="KDC_ERR_CLIENT_REVOKED")
        runner.run()
        assert "corp.local/Guest" in buf.getvalue()

    def test_invalid_users_not_written(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", user="nonexistent", output_file=buf)
        runner.kerberos.enumerate_user = lambda *_a, **_kw: AuthResult(success=False)
        runner.run()
        assert buf.getvalue() == ""

    def test_clock_skew_stops_execution(self, tmp_path) -> None:
        users_file = tmp_path / "users.txt"
        users_file.write_text("user1\nuser2\nuser3\n")
        call_count = 0

        def mock_enum(*_a, **_kw):
            nonlocal call_count
            call_count += 1
            return AuthResult(success=False, details="KRB_AP_ERR_SKEW")

        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", users_file=str(users_file))
        runner.kerberos.enumerate_user = mock_enum
        runner.run()
        assert call_count == 1
        assert runner._clock_skew is True

    def test_stop_on_success_works(self, tmp_path) -> None:
        users_file = tmp_path / "users.txt"
        users_file.write_text("user1\nuser2\nuser3\n")
        call_count = 0

        def mock_enum(*_a, **_kw):
            nonlocal call_count
            call_count += 1
            return AuthResult(success=True)

        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", users_file=str(users_file), stop_on_success=True, output_file=buf)
        runner.kerberos.enumerate_user = mock_enum
        runner.run()
        assert call_count == 1

    def test_users_file_iteration(self, tmp_path) -> None:
        users_file = tmp_path / "users.txt"
        users_file.write_text("admin\njohn\njane\n")
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", users_file=str(users_file), output_file=buf)
        runner.kerberos.enumerate_user = lambda *_a, **_kw: AuthResult(success=True)
        runner.run()
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 3

    def test_empty_users_file(self, tmp_path) -> None:
        users_file = tmp_path / "users.txt"
        users_file.write_text("\n  \n")
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", users_file=str(users_file), output_file=buf)
        runner.run()
        assert buf.getvalue() == ""

    def test_missing_user_source(self) -> None:
        buf = io.StringIO()
        runner = _make_runner(protocol=Protocol.USERENUM, kdc_ip="10.0.0.1", output_file=buf)
        runner.run()
        assert buf.getvalue() == ""


class TestTimeoutPropagation:
    def test_default_timeout(self) -> None:
        runner = _make_runner()
        assert runner.ntlm._timeout == 15
        assert runner.kerberos._timeout == 15

    def test_custom_timeout(self) -> None:
        runner = _make_runner(timeout=30.0)
        assert runner.ntlm._timeout == 30
        assert runner.kerberos._timeout == 30.0

    def test_zero_timeout_means_infinite(self) -> None:
        runner = _make_runner(timeout=0.0)
        assert runner.ntlm._timeout is None
        assert runner.kerberos._timeout is None
