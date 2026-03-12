"""Tests for credwolf.models."""

from __future__ import annotations

from credwolf.models import (
    AttackOptions,
    AuthenticationError,
    AuthResult,
    CredWolfError,
    EncryptionType,
    NtlmTransport,
    Protocol,
    TransportProtocol,
)


class TestEnums:
    def test_protocol_values(self) -> None:
        assert Protocol.NTLM == "ntlm"
        assert Protocol.KERBEROS == "kerberos"
        assert Protocol.USERENUM == "userenum"

    def test_ntlm_transport_values(self) -> None:
        assert NtlmTransport.SMB == "smb"
        assert NtlmTransport.LDAP == "ldap"
        assert NtlmTransport.LDAPS == "ldaps"

    def test_transport_protocol_values(self) -> None:
        assert TransportProtocol.UDP == "udp"
        assert TransportProtocol.TCP == "tcp"

    def test_encryption_type_values(self) -> None:
        assert EncryptionType.RC4 == "rc4"
        assert EncryptionType.AES128 == "aes128"
        assert EncryptionType.AES256 == "aes256"

    def test_protocol_from_string(self) -> None:
        assert Protocol("ntlm") == Protocol.NTLM
        assert Protocol("kerberos") == Protocol.KERBEROS
        assert Protocol("userenum") == Protocol.USERENUM

    def test_encryption_type_from_string(self) -> None:
        assert EncryptionType("rc4") == EncryptionType.RC4
        assert EncryptionType("aes128") == EncryptionType.AES128
        assert EncryptionType("aes256") == EncryptionType.AES256

    def test_ntlm_transport_from_string(self) -> None:
        assert NtlmTransport("smb") == NtlmTransport.SMB
        assert NtlmTransport("ldap") == NtlmTransport.LDAP
        assert NtlmTransport("ldaps") == NtlmTransport.LDAPS

    def test_transport_protocol_from_string(self) -> None:
        assert TransportProtocol("udp") == TransportProtocol.UDP
        assert TransportProtocol("tcp") == TransportProtocol.TCP


class TestAuthResult:
    def test_success_result(self) -> None:
        r = AuthResult(success=True)
        assert r.success is True
        assert r.details == ""

    def test_failed_result_with_details(self) -> None:
        r = AuthResult(success=False, details="disabled")
        assert r.success is False
        assert r.details == "disabled"

    def test_indeterminate_result(self) -> None:
        r = AuthResult(success=None, details="STATUS_ACCOUNT_DISABLED")
        assert r.success is None

    def test_frozen(self) -> None:
        r = AuthResult(success=True)
        try:
            r.success = False  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except AttributeError:
            pass

    def test_equality(self) -> None:
        assert AuthResult(success=True) == AuthResult(success=True)
        assert AuthResult(success=True) != AuthResult(success=False)
        assert AuthResult(success=True) != AuthResult(success=True, details="x")

    def test_details_default(self) -> None:
        r = AuthResult(success=False)
        assert r.details == ""


class TestAttackOptions:
    def test_defaults(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM)
        assert opts.delay == 0.0
        assert opts.jitter == 0.0
        assert opts.timeout == 15.0
        assert opts.max_lockouts == 0
        assert opts.stop_on_success is False
        assert opts.ntlm_transport == NtlmTransport.SMB
        assert opts.kdc_transport == TransportProtocol.UDP
        assert opts.etype == EncryptionType.RC4
        assert opts.verbosity == 0
        assert opts.hash_value is None
        assert opts.rc4_key is None
        assert opts.aes128_key is None
        assert opts.aes256_key is None
        assert opts.user_key_file is None

    def test_all_credential_fields_default_none(self) -> None:
        opts = AttackOptions(protocol=Protocol.NTLM)
        for field in ("user", "users_file", "password", "passwords_file", "hashes_file", "hash_value", "user_pass_file", "user_hash_file", "rc4_file", "aes128_file", "aes256_file", "rc4_key", "aes128_key", "aes256_key", "ticket", "user_key_file", "dc_ip", "kdc_ip", "domain", "output_file"):
            assert getattr(opts, field) is None, f"{field} should default to None"

    def test_kerberos_defaults(self) -> None:
        opts = AttackOptions(protocol=Protocol.KERBEROS, domain="corp.local")
        assert opts.protocol == Protocol.KERBEROS
        assert opts.domain == "corp.local"


class TestExceptions:
    def test_credwolf_error_is_exception(self) -> None:
        assert issubclass(CredWolfError, Exception)

    def test_authentication_error_is_credwolf_error(self) -> None:
        assert issubclass(AuthenticationError, CredWolfError)
