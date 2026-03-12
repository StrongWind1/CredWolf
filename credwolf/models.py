"""Data models, enumerations, and constants used across the package."""

from __future__ import annotations

import enum
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Protocol(enum.StrEnum):
    """Protocol used for the credential test."""

    NTLM = "ntlm"
    KERBEROS = "kerberos"
    USERENUM = "userenum"


class NtlmTransport(enum.StrEnum):
    """Application-layer protocol carrying NTLM authentication."""

    SMB = "smb"
    LDAP = "ldap"
    LDAPS = "ldaps"


class TransportProtocol(enum.StrEnum):
    """Transport protocol for Kerberos requests."""

    UDP = "udp"
    TCP = "tcp"


class EncryptionType(enum.StrEnum):
    """Kerberos encryption type."""

    RC4 = "rc4"
    AES128 = "aes128"
    AES256 = "aes256"


# ---------------------------------------------------------------------------
# Kerberos key hex lengths (characters, not bytes)
# ---------------------------------------------------------------------------

RC4_KEY_HEX_LEN = 32  # 16 bytes
AES128_KEY_HEX_LEN = 32  # 16 bytes (same as RC4 — cannot auto-distinguish)
AES256_KEY_HEX_LEN = 64  # 32 bytes

# ---------------------------------------------------------------------------
# Immutable result record returned by authentication helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthResult:
    """Outcome of a single credential test.

    *success* can be ``True`` (valid), ``False`` (invalid), or ``None``
    (indeterminate, e.g. network error or disabled account).
    """

    success: bool | None
    details: str = ""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CredWolfError(Exception):
    """Base exception for all credwolf errors."""


class AuthenticationError(CredWolfError):
    """Raised when an authentication step fails fatally."""


# ---------------------------------------------------------------------------
# Configuration container
# ---------------------------------------------------------------------------


@dataclass
class AttackOptions:
    """Runtime options consumed by the attack orchestrator."""

    protocol: Protocol
    domain: str | None = None
    dc_ip: str | None = None
    kdc_ip: str | None = None
    ntlm_transport: NtlmTransport = NtlmTransport.SMB
    kdc_transport: TransportProtocol = TransportProtocol.UDP
    etype: EncryptionType = EncryptionType.RC4
    # Credential sources (file paths / single values)
    user: str | None = None
    users_file: str | None = None
    password: str | None = None
    passwords_file: str | None = None
    hashes_file: str | None = None
    hash_value: str | None = None
    user_pass_file: str | None = None
    user_hash_file: str | None = None
    rc4_file: str | None = None
    aes128_file: str | None = None
    aes256_file: str | None = None
    rc4_key: str | None = None
    aes128_key: str | None = None
    aes256_key: str | None = None
    ticket: str | None = None
    user_key_file: str | None = None
    # Behavior
    stop_on_success: bool = False
    delay: float = 0.0
    jitter: float = 0.0
    timeout: float = 15.0
    max_lockouts: int = 0
    verbosity: int = 0
    output_file: str | None = None
