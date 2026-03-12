"""Tests for CLI argument parsing and validation."""

from __future__ import annotations

import pytest

from credwolf.cli import _build_parser, _namespace_to_options, _validate
from credwolf.models import EncryptionType, NtlmTransport, Protocol, TransportProtocol


class TestParserBuilds:
    def test_build_parser(self) -> None:
        parser, ntlm_parser, kerberos_parser, userenum_parser = _build_parser()
        assert parser is not None
        assert ntlm_parser is not None
        assert kerberos_parser is not None
        assert userenum_parser is not None


# ======================================================================
# NTLM subcommand
# ======================================================================


class TestNtlmSubcommand:
    def test_single_user_single_password(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.protocol == "ntlm"
        assert ns.user == "admin"
        assert ns.password == "Pass1"
        assert ns.domain == "corp.local"
        assert ns.dc_ip == "10.0.0.1"

    def test_single_user_password_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-P", "pass.txt"])
        assert ns.passwords_file == "pass.txt"

    def test_single_user_hash_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-H", "hashes.txt"])
        assert ns.hashes_file == "hashes.txt"

    def test_user_file_single_password(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-U", "users.txt", "-p", "Pass1"])
        assert ns.users_file == "users.txt"
        assert ns.password == "Pass1"

    def test_user_file_password_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-U", "users.txt", "-P", "pass.txt"])
        assert ns.users_file == "users.txt"
        assert ns.passwords_file == "pass.txt"

    def test_user_file_hash_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-U", "users.txt", "-H", "hashes.txt"])
        assert ns.users_file == "users.txt"
        assert ns.hashes_file == "hashes.txt"

    def test_user_pass_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--user-pass-file", "creds.txt"])
        assert ns.user_pass_file == "creds.txt"

    def test_user_hash_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--user-hash-file", "creds.txt"])
        assert ns.user_hash_file == "creds.txt"

    def test_empty_password_parsed(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", ""])
        assert ns.password == ""

    def test_single_user_single_hash(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "--hash", "aabbccdd11223344aabbccdd11223344"])
        assert ns.hash_value == "aabbccdd11223344aabbccdd11223344"

    def test_user_file_single_hash(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-U", "users.txt", "--hash", "aa:bb"])
        assert ns.users_file == "users.txt"
        assert ns.hash_value == "aa:bb"

    def test_transport_ldaps(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "--transport", "ldaps"])
        assert ns.ntlm_transport == "ldaps"


# ======================================================================
# Kerberos subcommand
# ======================================================================


class TestKerberosSubcommand:
    def test_single_user_single_password(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.protocol == "kerberos"
        assert ns.user == "admin"
        assert ns.password == "Pass1"

    def test_user_file_password_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "-P", "pass.txt"])
        assert ns.users_file == "users.txt"
        assert ns.passwords_file == "pass.txt"

    def test_user_file_single_password(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "-p", "Pass1"])
        assert ns.users_file == "users.txt"
        assert ns.kdc_transport == "udp"
        assert ns.etype == "rc4"

    def test_rc4_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--rc4-file", "rc4.txt"])
        assert ns.rc4_file == "rc4.txt"

    def test_aes_keys(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--aes256-file", "keys.txt", "--transport", "tcp", "-e", "aes256"])
        assert ns.aes256_file == "keys.txt"
        assert ns.kdc_transport == "tcp"
        assert ns.etype == "aes256"

    def test_multiple_key_lists(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--rc4-file", "rc4.txt", "--aes256-file", "aes256.txt"])
        assert ns.rc4_file == "rc4.txt"
        assert ns.aes256_file == "aes256.txt"

    def test_ticket_ccache(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--ticket", "admin.ccache"])
        assert ns.ticket == "admin.ccache"
        assert ns.user == "admin"

    def test_ticket_kirbi(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--ticket", "admin.kirbi"])
        assert ns.ticket == "admin.kirbi"

    def test_ticket_with_user_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--ticket", "krb.ccache"])
        assert ns.ticket == "krb.ccache"
        assert ns.users_file == "users.txt"

    def test_inline_key_with_user_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--aes128-key", "b" * 32])
        assert ns.users_file == "users.txt"
        assert ns.aes128_key == "b" * 32

    def test_inline_rc4_key(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--rc4-key", "a" * 32])
        assert ns.rc4_key == "a" * 32

    def test_inline_aes128_key(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--aes128-key", "b" * 32])
        assert ns.aes128_key == "b" * 32

    def test_inline_aes256_key(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--aes256-key", "c" * 64])
        assert ns.aes256_key == "c" * 64

    def test_user_key_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--user-key-file", "pairs.txt"])
        assert ns.user_key_file == "pairs.txt"


# ======================================================================
# Global flags
# ======================================================================


class TestGlobalFlags:
    def test_verbose_count(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-vv", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.verbosity == 2

    def test_verbose_triple(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-vvv", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.verbosity == 3

    def test_stop_on_success(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--stop-on-success", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.stop_on_success is True

    def test_delay_and_jitter(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--delay", "1.5", "--jitter", "0.5", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.delay == 1.5
        assert ns.jitter == 0.5

    def test_output_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "-o", "results.txt", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.output_file == "results.txt"

    def test_timeout_default(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.timeout == 15

    def test_timeout_custom(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--timeout", "60", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.timeout == 60

    def test_timeout_zero(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--timeout", "0", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.timeout == 0

    def test_max_lockouts_default(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.max_lockouts == 0

    def test_max_lockouts_custom(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--max-lockouts", "5", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        assert ns.max_lockouts == 5

    def test_missing_protocol_exits(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_missing_domain_exits(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])


# ======================================================================
# Mutual exclusivity
# ======================================================================


class TestNtlmMutualExclusivity:
    def test_u_and_U_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-U", "users.txt", "-p", "Pass1"])

    def test_p_and_P_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "-P", "pass.txt"])

    def test_p_and_H_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "-H", "hashes.txt"])

    def test_P_and_H_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-P", "pass.txt", "-H", "hashes.txt"])

    def test_user_pass_file_and_user_hash_file_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--user-pass-file", "a.txt", "--user-hash-file", "b.txt"])

    def test_hash_and_p_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "--hash", "aabb", "-p", "Pass1"])

    def test_hash_and_P_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "--hash", "aabb", "-P", "p.txt"])

    def test_hash_and_user_pass_file_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--hash", "aabb", "--user-pass-file", "c.txt"])

    def test_hash_and_H_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "--hash", "aabb", "-H", "h.txt"])

    def test_hash_valid_with_user(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "--hash", "aabbccdd11223344aabbccdd11223344"])
        _validate(ns, p, np, kp, up)  # should not raise

    def test_colon_file_rejects_u(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--user-pass-file", "creds.txt"])
        # This parses OK (no argparse conflict), but _validate rejects it
        # only if -u is also set. Here -u is NOT set, so it should pass.
        _validate(ns, p, np, kp, up)  # should not raise

    def test_colon_file_with_u_rejected(self) -> None:
        """user-pass-file + -u is caught by validation."""
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--user-pass-file", "creds.txt", "-u", "admin"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)


class TestKerberosMutualExclusivity:
    def test_u_and_U_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-U", "users.txt", "-p", "Pass1"])

    def test_password_and_key_list_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "--rc4-file", "rc4.txt"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_password_and_ticket_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "--ticket", "a.ccache"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_key_list_and_ticket_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--rc4-file", "rc4.txt", "--ticket", "a.ccache"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_user_key_file_rejects_u(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--user-key-file", "pairs.txt", "-u", "admin"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_user_key_file_rejects_password(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--user-key-file", "pairs.txt", "-p", "Pass1"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_missing_secret_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_missing_user_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-p", "Pass1"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_inline_key_and_password_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--rc4-key", "a" * 32, "-p", "Pass1"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_inline_key_and_key_list_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--rc4-key", "a" * 32, "--rc4-file", "rc4.txt"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_inline_key_and_ticket_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--aes256-key", "c" * 64, "--ticket", "a.ccache"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_user_key_file_rejects_inline_key(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--user-key-file", "pairs.txt", "--rc4-key", "a" * 32])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_inline_key_valid(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--rc4-key", "a" * 32])
        _validate(ns, p, np, kp, up)  # should not raise

    def test_p_and_P_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "-P", "pass.txt"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_inline_key_requires_user(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--rc4-key", "a" * 32])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_user_key_file_rejects_U(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--user-key-file", "pairs.txt", "-U", "users.txt"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_multiple_inline_keys_valid(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--rc4-key", "a" * 32, "--aes256-key", "c" * 64])
        _validate(ns, p, np, kp, up)  # should not raise

    def test_multiple_key_lists_allowed(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--rc4-file", "rc4.txt", "--aes256-file", "aes.txt"])
        _validate(ns, p, np, kp, up)  # should NOT raise


# ======================================================================
# Namespace → options
# ======================================================================


class TestNamespaceToOptions:
    def test_ntlm_conversion(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.protocol == "ntlm"
        assert opts.user == "admin"
        assert opts.password == "Pass1"
        assert opts.domain == "corp.local"

    def test_kerberos_conversion(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.protocol == "kerberos"
        assert opts.users_file == "users.txt"

    def test_kerberos_single_user(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.user == "admin"

    def test_ntlm_hash_value(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "--hash", "aabbccdd11223344aabbccdd11223344"])
        opts = _namespace_to_options(ns)
        assert opts.hash_value == "aabbccdd11223344aabbccdd11223344"

    def test_kerberos_inline_keys(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "--aes256-key", "c" * 64])
        opts = _namespace_to_options(ns)
        assert opts.aes256_key == "c" * 64

    def test_ntlm_enum_conversion(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "--transport", "ldaps"])
        opts = _namespace_to_options(ns)
        assert opts.ntlm_transport == NtlmTransport.LDAPS
        assert isinstance(opts.ntlm_transport, NtlmTransport)

    def test_kerberos_enum_conversion(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1", "-e", "aes256", "--transport", "tcp"])
        opts = _namespace_to_options(ns)
        assert opts.etype == EncryptionType.AES256
        assert isinstance(opts.etype, EncryptionType)
        assert opts.kdc_transport == TransportProtocol.TCP
        assert isinstance(opts.kdc_transport, TransportProtocol)

    def test_output_file_propagation(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "-o", "out.txt", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.output_file == "out.txt"

    def test_global_flags_propagation(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--delay", "1.5", "--jitter", "0.5", "--stop-on-success", "-vv", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.delay == 1.5
        assert opts.jitter == 0.5
        assert opts.stop_on_success is True
        assert opts.verbosity == 2

    def test_timeout_propagation(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--timeout", "60", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.timeout == 60

    def test_max_lockouts_propagation(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["--max-lockouts", "5", "-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", "Pass1"])
        opts = _namespace_to_options(ns)
        assert opts.max_lockouts == 5


# ======================================================================
# Validation edge cases
# ======================================================================


class TestValidation:
    def test_missing_protocol(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_ntlm_missing_user(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-p", "Pass1"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_ntlm_missing_secret(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_ntlm_hash_missing_user(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--hash", "aabbccdd11223344aabbccdd11223344"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_kerberos_inline_key_missing_user(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--rc4-key", "a" * 32])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_ntlm_empty_password_valid(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "-u", "admin", "-p", ""])
        _validate(ns, p, np, kp, up)  # should not raise

    def test_ntlm_user_pass_file_standalone(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "ntlm", "--dc-ip", "10.0.0.1", "--user-hash-file", "creds.txt"])
        _validate(ns, p, np, kp, up)  # should not raise

    def test_kerberos_user_key_file_standalone(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "kerberos", "--kdc-ip", "10.0.0.1", "--user-key-file", "pairs.txt"])
        _validate(ns, p, np, kp, up)  # should not raise


# ======================================================================
# Userenum subcommand
# ======================================================================


class TestUserenumSubcommand:
    def test_single_user(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-u", "Administrator"])
        assert ns.protocol == "userenum"
        assert ns.user == "Administrator"
        assert ns.kdc_ip == "10.0.0.1"

    def test_users_file(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-U", "users.txt"])
        assert ns.users_file == "users.txt"

    def test_kdc_ip_required(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "userenum", "-u", "admin"])

    def test_transport_default_udp(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-u", "admin"])
        assert ns.kdc_transport == "udp"

    def test_transport_tcp(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-u", "admin", "--transport", "tcp"])
        assert ns.kdc_transport == "tcp"

    def test_u_and_U_rejected(self) -> None:
        p, _, _, _ = _build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-u", "admin", "-U", "users.txt"])


class TestUserenumValidation:
    def test_missing_user_source_rejected(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1"])
        with pytest.raises(SystemExit):
            _validate(ns, p, np, kp, up)

    def test_single_user_valid(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-u", "admin"])
        _validate(ns, p, np, kp, up)  # should not raise

    def test_users_file_valid(self) -> None:
        p, np, kp, up = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-U", "users.txt"])
        _validate(ns, p, np, kp, up)  # should not raise


class TestUserenumNamespaceToOptions:
    def test_userenum_conversion(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-u", "admin"])
        opts = _namespace_to_options(ns)
        assert opts.protocol == Protocol.USERENUM
        assert opts.user == "admin"
        assert opts.kdc_ip == "10.0.0.1"
        assert opts.kdc_transport == TransportProtocol.UDP

    def test_userenum_tcp_conversion(self) -> None:
        p, _, _, _ = _build_parser()
        ns = p.parse_args(["-d", "corp.local", "userenum", "--kdc-ip", "10.0.0.1", "-U", "users.txt", "--transport", "tcp"])
        opts = _namespace_to_options(ns)
        assert opts.protocol == Protocol.USERENUM
        assert opts.users_file == "users.txt"
        assert opts.kdc_transport == TransportProtocol.TCP
