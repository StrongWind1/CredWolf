# SPDX-License-Identifier: Apache-2.0
"""Tests for CLI header output, _describe_user, and _describe_secret."""

from __future__ import annotations

from credwolf.cli import _describe_secret, _describe_user, _print_header
from credwolf.models import (
    AttackOptions,
    EncryptionType,
    NtlmTransport,
    Protocol,
    TransportProtocol,
)

# ======================================================================
# _describe_user
# ======================================================================


class TestDescribeUser:
    def test_single_user(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, user="admin")
        assert _describe_user(opts) == "admin (inline)"

    def test_users_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, users_file="users.txt")
        assert _describe_user(opts) == "file (users.txt)"

    def test_user_pass_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, user_pass_file="creds.txt")
        assert _describe_user(opts) == "paired"

    def test_user_hash_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, user_hash_file="creds.txt")
        assert _describe_user(opts) == "paired"

    def test_user_key_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, user_key_file="pairs.txt")
        assert _describe_user(opts) == "paired"

    def test_no_user(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM)
        assert _describe_user(opts) == "-"


# ======================================================================
# _describe_secret
# ======================================================================


class TestDescribeSecret:
    def test_password_inline(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, password="Pass1")
        assert _describe_secret(opts) == "password (inline)"

    def test_empty_password_inline(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, password="")
        assert _describe_secret(opts) == "password (inline)"

    def test_passwords_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, passwords_file="pass.txt")
        assert _describe_secret(opts) == "password (pass.txt)"

    def test_hashes_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, hashes_file="hashes.txt")
        assert _describe_secret(opts) == "nt_hash (hashes.txt)"

    def test_hash_value_inline(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, hash_value="aabbccdd11223344aabbccdd11223344")
        assert _describe_secret(opts) == "nt_hash (inline)"

    def test_user_pass_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, user_pass_file="creds.txt")
        assert _describe_secret(opts) == "user:password (creds.txt)"

    def test_user_hash_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, user_hash_file="creds.txt")
        assert _describe_secret(opts) == "user:nt_hash (creds.txt)"

    def test_user_key_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, user_key_file="pairs.txt")
        assert _describe_secret(opts) == "user:key (pairs.txt)"

    def test_rc4_key_inline(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, rc4_key="a" * 32)
        assert _describe_secret(opts) == "rc4_key (inline)"

    def test_aes128_key_inline(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, aes128_key="b" * 32)
        assert _describe_secret(opts) == "aes128_key (inline)"

    def test_aes256_key_inline(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, aes256_key="c" * 64)
        assert _describe_secret(opts) == "aes256_key (inline)"

    def test_multiple_inline_keys(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, rc4_key="a" * 32, aes256_key="c" * 64)
        assert _describe_secret(opts) == "rc4_key, aes256_key (inline)"

    def test_all_three_inline_keys(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, rc4_key="a" * 32, aes128_key="b" * 32, aes256_key="c" * 64)
        assert _describe_secret(opts) == "rc4_key, aes128_key, aes256_key (inline)"

    def test_rc4_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, rc4_file="rc4.txt")
        assert _describe_secret(opts) == "rc4_key (rc4.txt)"

    def test_aes256_file(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, aes256_file="aes256.txt")
        assert _describe_secret(opts) == "aes256_key (aes256.txt)"

    def test_multiple_key_files(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, rc4_file="rc4.txt", aes256_file="aes.txt")
        assert _describe_secret(opts) == "rc4_key (rc4.txt), aes256_key (aes.txt)"

    def test_all_three_key_files(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, rc4_file="rc4.txt", aes128_file="a128.txt", aes256_file="a256.txt")
        assert _describe_secret(opts) == "rc4_key (rc4.txt), aes128_key (a128.txt), aes256_key (a256.txt)"

    def test_ticket(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, ticket="admin.ccache")
        assert _describe_secret(opts) == "ticket (admin.ccache)"

    def test_no_secret(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM)
        assert _describe_secret(opts) == "-"


# ======================================================================
# _print_header
# ======================================================================


class TestPrintHeader:
    def test_ntlm_smb_password(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="evil.corp", dc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "credwolf v" in out
        assert "Protocol  : ntlm" in out
        assert "Transport : smb" in out
        assert "Domain    : evil.corp" in out
        assert "Target    : 10.0.0.1" in out
        assert "User      : admin (inline)" in out
        assert "Secret    : password (inline)" in out
        assert "Etype" not in out

    def test_ntlm_ldaps_transport(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", ntlm_transport=NtlmTransport.LDAPS, user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Transport : ldaps" in out

    def test_ntlm_ldap_transport(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", ntlm_transport=NtlmTransport.LDAP, user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Transport : ldap" in out

    def test_ntlm_users_file_passwords_file(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", users_file="users.txt", passwords_file="pass.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "User      : file (users.txt)" in out
        assert "Secret    : password (pass.txt)" in out

    def test_ntlm_hash_file(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", users_file="users.txt", hashes_file="hashes.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Secret    : nt_hash (hashes.txt)" in out

    def test_ntlm_inline_hash(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", hash_value="aabb")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Secret    : nt_hash (inline)" in out

    def test_ntlm_user_pass_file(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user_pass_file="creds.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "User      : paired" in out
        assert "Secret    : user:password (creds.txt)" in out

    def test_ntlm_user_hash_file(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user_hash_file="creds.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "User      : paired" in out
        assert "Secret    : user:nt_hash (creds.txt)" in out

    def test_kerberos_password_udp_rc4(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="evil.corp", kdc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Protocol  : kerberos" in out
        assert "Transport : udp" in out
        assert "Etype     : rc4" in out
        assert "Domain    : evil.corp" in out
        assert "Target    : 10.0.0.1" in out
        assert "User      : admin (inline)" in out
        assert "Secret    : password (inline)" in out

    def test_kerberos_aes256_tcp(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="evil.corp", kdc_ip="10.0.0.1", kdc_transport=TransportProtocol.TCP, etype=EncryptionType.AES256, user="admin", aes256_key="c" * 64)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Transport : tcp" in out
        assert "Etype     : aes256" in out
        assert "Secret    : aes256_key (inline)" in out

    def test_kerberos_aes128_etype(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="corp.local", kdc_ip="10.0.0.1", etype=EncryptionType.AES128, user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Etype     : aes128" in out

    def test_kerberos_user_key_file(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="corp.local", kdc_ip="10.0.0.1", user_key_file="pairs.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "User      : paired" in out
        assert "Secret    : user:key (pairs.txt)" in out

    def test_kerberos_ticket(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="corp.local", kdc_ip="10.0.0.1", user="admin", ticket="admin.ccache")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Secret    : ticket (admin.ccache)" in out

    def test_kerberos_multiple_key_lists(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="corp.local", kdc_ip="10.0.0.1", users_file="users.txt", rc4_file="rc4.txt", aes256_file="aes.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Secret    : rc4_key (rc4.txt), aes256_key (aes.txt)" in out

    def test_delay_shown(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", delay=2.0)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Delay     : 2.0s" in out

    def test_delay_with_jitter(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", delay=1.5, jitter=0.5)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Delay     : 1.5s (+/- 0.5s jitter)" in out

    def test_jitter_only(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", jitter=0.3)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Delay" in out
        assert "0.3s jitter" in out

    def test_no_delay_hidden(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Delay" not in out

    def test_stop_on_success_shown(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", stop_on_success=True)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Stop      : on first success" in out

    def test_stop_on_success_hidden_when_false(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Stop" not in out

    def test_output_file_shown(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", output_file="results.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Output    : results.txt" in out

    def test_output_file_hidden_when_unset(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Output" not in out

    def test_target_falls_back_to_domain(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Target    : corp.local" in out

    def test_kerberos_target_fallback(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="evil.corp", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Target    : evil.corp" in out

    def test_timeout_shown_when_non_default(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", timeout=60.0)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Timeout   : 60.0s" in out

    def test_timeout_infinite_shown(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", timeout=0.0)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Timeout   : none (infinite)" in out

    def test_timeout_hidden_when_default(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Timeout" not in out

    def test_max_lockouts_shown(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1", max_lockouts=5)
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Lockouts  : stop after 5 consecutive" in out

    def test_max_lockouts_hidden_when_zero(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM, domain="corp.local", dc_ip="10.0.0.1", user="admin", password="Pass1")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Lockouts" not in out

    def test_userenum_header(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.USERENUM, domain="evil.corp", kdc_ip="10.0.0.1", user="Administrator")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Protocol  : userenum" in out
        assert "Transport : udp" in out
        assert "Domain    : evil.corp" in out
        assert "Target    : 10.0.0.1" in out
        assert "User      : Administrator (inline)" in out
        assert "Etype" not in out
        assert "Secret" not in out

    def test_userenum_header_tcp(self, capsys) -> None:
        opts = AttackOptions(protocol=Protocol.USERENUM, domain="evil.corp", kdc_ip="10.0.0.1", kdc_transport=TransportProtocol.TCP, users_file="users.txt")
        _print_header(opts)
        out = capsys.readouterr().out
        assert "Protocol  : userenum" in out
        assert "Transport : tcp" in out
        assert "User      : file (users.txt)" in out
