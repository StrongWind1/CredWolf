# SPDX-License-Identifier: Apache-2.0
"""NTLM authentication helpers (SMB and LDAP/LDAPS)."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from impacket.ldap import ldap as impacket_ldap
from impacket.smbconnection import SessionError, SMBConnection

from credwolf.models import AuthResult, NtlmTransport

if TYPE_CHECKING:
    from credwolf.log import Logger

_DEFAULT_TIMEOUT = 15


class NtlmHandler:
    """NTLM authentication via SMB or LDAP/LDAPS."""

    # SMB status codes returned AFTER password validation succeeds.
    # These confirm the credential is correct — a post-auth restriction
    # (disabled account, expired password, logon hours, etc.) blocked the logon.
    _PASSWORD_CONFIRMED_STATUSES: frozenset[str] = frozenset(
        {
            "STATUS_PASSWORD_MUST_CHANGE",
            "STATUS_PASSWORD_EXPIRED",
            "STATUS_ACCOUNT_DISABLED",
            "STATUS_ACCOUNT_EXPIRED",
            "STATUS_INVALID_LOGON_HOURS",
            "STATUS_INVALID_WORKSTATION",
        }
    )

    def __init__(self, logger: Logger, timeout: float = _DEFAULT_TIMEOUT) -> None:
        """Initialize the handler with a logger and connection timeout."""
        self.logger = logger
        # SMBConnection passes timeout to socket.settimeout().
        # settimeout(0) = non-blocking (broken), settimeout(None) = blocking (infinite).
        self._timeout: int | None = None if timeout == 0 else int(timeout)

    def test_credentials(
        self,
        target: str,
        domain: str,
        user: str,
        password: str | None,
        lm_hash: str | None,
        nt_hash: str | None,
        transport: NtlmTransport,
    ) -> AuthResult:
        """Test credentials via the specified transport and return an :class:`AuthResult`."""
        if transport == NtlmTransport.SMB:
            return self._smb_auth(target, domain, user, password, lm_hash, nt_hash)
        return self._ldap_auth(target, domain, user, password, lm_hash, nt_hash, transport)

    # -- SMB ----------------------------------------------------------------

    def _smb_auth(
        self,
        target: str,
        domain: str,
        user: str,
        password: str | None,
        lm_hash: str | None,
        nt_hash: str | None,
    ) -> AuthResult:
        if not target:
            self.logger.error("No target was set. Use -d/--domain or --dc-ip.")
            return AuthResult(success=False)

        try:
            self.logger.debug(f"Connecting to smb://{target}:445")
            smb_conn = SMBConnection(target, target, None, 445, timeout=self._timeout)
        except OSError as exc:
            self.logger.error(f"Cannot connect to smb://{target}:445 — {exc}")
            return AuthResult(success=False, details="connection failed")
        except Exception as exc:
            self.logger.error(f"Cannot connect to smb://{target}:445 — {exc}")
            return AuthResult(success=False, details="connection failed")

        nt_hash = nt_hash or ""
        lm_hash = lm_hash or ""
        try:
            self.logger.debug(
                f"Logging in domain={domain} user={user} lm_hash={'<set>' if lm_hash else '<none>'} nt_hash={'<set>' if nt_hash else '<none>'}",
            )
            smb_conn.login(
                domain=domain,
                user=user,
                password=password or "",
                lmhash=lm_hash,
                nthash=nt_hash,
            )
            return AuthResult(success=True)
        except SessionError as exc:
            error_code, _desc = exc.getErrorString()
            if error_code == "STATUS_LOGON_FAILURE":
                self.logger.debug(f"User {user} — STATUS_LOGON_FAILURE (wrong password or user)")
                return AuthResult(success=False)
            # These statuses are returned AFTER password validation —
            # the credential is correct but a secondary check failed.
            if error_code in self._PASSWORD_CONFIRMED_STATUSES:
                self.logger.debug(f"User {user} — {error_code} (password correct, post-auth restriction)")
                return AuthResult(success=True, details=error_code)
            # Anything else is indeterminate (e.g. STATUS_ACCOUNT_LOCKED_OUT
            # is returned before password validation on most AD versions).
            self.logger.debug(f"User {user} — {error_code}")
            return AuthResult(success=None, details=error_code)
        finally:
            smb_conn.close()

    # -- LDAP / LDAPS -------------------------------------------------------

    def _ldap_auth(
        self,
        target: str,
        domain: str,
        user: str,
        password: str | None,
        lm_hash: str | None,
        nt_hash: str | None,
        transport: NtlmTransport,
    ) -> AuthResult:
        nt_hash = nt_hash or ""
        lm_hash = lm_hash or ""
        scheme = "ldaps" if transport == NtlmTransport.LDAPS else "ldap"

        ldap_conn = None
        try:
            self.logger.debug(f"Connecting to {scheme}://{target}")
            ldap_conn = impacket_ldap.LDAPConnection(url=f"{scheme}://{target}")
            self.logger.debug(f"Logging in domain={domain} user={user}")
            ldap_conn.login(
                domain=domain,
                user=user,
                password=password or "",
                lmhash=lm_hash,
                nthash=nt_hash,
            )
            return AuthResult(success=True)
        except impacket_ldap.LDAPSessionError as exc:
            if "strongerAuthRequired" in str(exc):
                self.logger.debug("Stronger auth required — retrying with LDAPS")
                return self._ldaps_retry(target, domain, user, password, lm_hash, nt_hash)
            self.logger.debug("LDAP session error — credentials likely invalid")
            return AuthResult(success=False)
        except OSError as exc:
            self.logger.error(f"Cannot connect to {scheme}://{target} — {exc}")
            return AuthResult(success=False, details="connection failed")
        except Exception as exc:
            self.logger.error(f"Cannot connect to {scheme}://{target} — {exc}")
            return AuthResult(success=False, details="connection failed")
        finally:
            if ldap_conn is not None:
                with contextlib.suppress(Exception):
                    ldap_conn.close()

    def _ldaps_retry(
        self,
        target: str,
        domain: str,
        user: str,
        password: str | None,
        lm_hash: str,
        nt_hash: str,
    ) -> AuthResult:
        ldap_conn = None
        try:
            ldap_conn = impacket_ldap.LDAPConnection(url=f"ldaps://{target}")
            ldap_conn.login(
                domain=domain,
                user=user,
                password=password or "",
                lmhash=lm_hash,
                nthash=nt_hash,
            )
            return AuthResult(success=True)
        except impacket_ldap.LDAPSessionError:
            return AuthResult(success=False)
        except Exception as exc:
            self.logger.error(f"Cannot connect to ldaps://{target} — {exc}")
            return AuthResult(success=False, details="connection failed")
        finally:
            if ldap_conn is not None:
                with contextlib.suppress(Exception):
                    ldap_conn.close()
