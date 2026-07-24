# SPDX-License-Identifier: Apache-2.0
"""Kerberos pre-authentication helpers.

Why we don't use ``getKerberosTGT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Impacket exports ``getKerberosTGT()`` which performs the full AS exchange
(salt retrieval + pre-auth + TGT extraction).  However, it depends on
``sendReceive()`` which is **TCP-only**.  credwolf defaults to UDP for
Kerberos (matching the protocol's default) and offers ``--transport tcp``
as an option.  We therefore implement our own transport layer with both
TCP and UDP support, and build the AS-REQ messages ourselves.

What we DO delegate to Impacket:

- ``getKerberosTGS()`` — TGS-REQ for ticket validation (via Impacket's TCP transport)
- ``CCache.loadFile()`` / ``CCache.loadKirbiFile()`` — ticket file loading
- ``Key``, ``_enctype_table``, ``cipher.string_to_key()`` — key derivation and encryption
- ``compute_nthash()`` — RC4 key derivation from password
- All ASN.1 types (``AS_REQ``, ``PA_ENC_TS_ENC``, ``EncryptedData``, etc.)

Protocol flow overview
~~~~~~~~~~~~~~~~~~~~~~
credwolf validates Kerberos credentials by performing **pre-authentication**
(the first step of a normal Kerberos AS exchange).  The number of KDC requests
per credential depends on the credential type:

**Password with RC4 etype (1 request)**
    The key is the NT hash of the password — no salt is required.  credwolf
    sends a single AS-REQ containing an encrypted timestamp.  If the KDC
    returns an AS-REP, the credential is valid.

**Password with AES128/AES256 etype (1-2 requests)**
    AES key derivation requires a salt (typically ``REALM.UPPERuser``).  On the
    first attempt for each user, credwolf sends a "bare" AS-REQ *without*
    pre-auth data.  The KDC replies with ``KDC_ERR_PREAUTH_REQUIRED`` and
    includes the salt in the error's e-data.  credwolf caches this salt per
    user so subsequent passwords for the **same user** only need 1 request.
    The bare AS-REQ is **not** a login attempt and does **not** increment the
    bad-password counter.

**Raw key — RC4, AES128, or AES256 (1 request)**
    The key is used directly; no salt retrieval is needed.

**Ticket file — ccache or kirbi (1 request)**
    A TGS-REQ is sent using the TGT from the ticket file.  This validates
    that the ticket is still accepted by the KDC.  No password counter impact.

Account lockout
~~~~~~~~~~~~~~~
Only the AS-REQ that carries an encrypted timestamp is treated as a login
attempt by the KDC.  A wrong key causes ``KDC_ERR_PREAUTH_FAILED`` and one
increment of the bad-password counter.  The salt-retrieval request carries no
authentication data and is harmless.
"""

from __future__ import annotations

import binascii
import datetime
import secrets
import socket
import struct
from binascii import unhexlify
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AS_REP,
    AS_REQ,
    ETYPE_INFO,
    ETYPE_INFO2,
    KRB_ERROR,
    METHOD_DATA,
    PA_ENC_TS_ENC,
    EncryptedData,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal
from impacket.ntlm import compute_nthash
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import Sequence, noValue
from pyasn1.type.useful import GeneralizedTime

from credwolf.models import AuthResult, EncryptionType

if TYPE_CHECKING:
    from credwolf.log import Logger

# ---------------------------------------------------------------------------
# Impacket constant helpers
# ---------------------------------------------------------------------------
# Impacket enums expose ``.value`` as an untyped attribute.  These helpers
# extract the integer value with an explicit cast so the rest of the module
# can treat them as plain ``int``.


def _etype_int(enum_member: Any) -> int:
    return int(cast("int", enum_member.value))


def _const_int(parent: str, name: str) -> int:
    return int(cast("int", getattr(getattr(constants, parent), name).value))


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

# Encryption-type integers used in AS-REQ etype fields.
_ETYPE_MAP: dict[EncryptionType, int] = {
    EncryptionType.RC4: _etype_int(constants.EncryptionTypes.rc4_hmac),
    EncryptionType.AES128: _etype_int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96),
    EncryptionType.AES256: _etype_int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96),
}

# Principal name types.
_NT_PRINCIPAL = _const_int("PrincipalNameType", "NT_PRINCIPAL")
_NT_SRV_INST = _const_int("PrincipalNameType", "NT_SRV_INST")

# AS-REQ message tag and default KDC option flags.
_AS_REQ_TAG = _const_int("ApplicationTagNumbers", "AS_REQ")
_KDC_OPTS = [
    _const_int("KDCOptions", "forwardable"),
    _const_int("KDCOptions", "renewable"),
    _const_int("KDCOptions", "proxiable"),
]

# Pre-authentication data type identifiers.
_PA_ENC_TIMESTAMP = _const_int("PreAuthenticationDataTypes", "PA_ENC_TIMESTAMP")
_PA_ETYPE_INFO2 = _const_int("PreAuthenticationDataTypes", "PA_ETYPE_INFO2")
_PA_ETYPE_INFO = _const_int("PreAuthenticationDataTypes", "PA_ETYPE_INFO")

# The KDC replies with this error when pre-auth is required but the request
# contained none.  This is the *expected* response for salt retrieval.
_KDC_ERR_PREAUTH_REQUIRED = _const_int("ErrorCodes", "KDC_ERR_PREAUTH_REQUIRED")

# Ticket file format magic bytes (first byte of the file).
_CCACHE_MAGIC = 0x05  # MIT ccache format
_KIRBI_MAGIC = 0x76  # Mimikatz KRB-CRED (ASN.1 APPLICATION 22)

_KDC_PORT = 88
_DEFAULT_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class KerberosHandler:
    """Kerberos pre-authentication and ticket validation.

    Maintains per-session caches so that:

    * **Salts** are retrieved once per user (avoiding redundant bare AS-REQs).
    * **Unknown / revoked users** are remembered so subsequent attempts for
      the same user are skipped without network traffic.
    """

    def __init__(self, logger: Logger, timeout: float = _DEFAULT_TIMEOUT) -> None:
        """Initialize the handler with a logger and connection timeout."""
        self.logger = logger
        self._timeout: float | None = None if timeout == 0 else timeout

        # Per-user salt cache: ``{username: {etype_int: salt_bytes}}``.
        # Populated by ``_get_salts`` on the first AES attempt for each user.
        self.salts: dict[str, dict[int, bytes]] = {}

        # Per-user s2kparams cache: ``{username: {etype_int: params_bytes}}``.
        # Extracted from ETYPE-INFO2 (RFC 4120 §5.2.7.5).  Contains the
        # opaque string-to-key parameters (e.g., PBKDF2 iteration count
        # for AES per RFC 3962).
        self.s2kparams: dict[str, dict[int, bytes | None]] = {}

        # Correct username casing extracted from ETYPE-INFO2 salts.
        # Maps ``input_username`` → ``exact_username`` as stored in AD.
        self.username_corrections: dict[str, str] = {}

        # Users whose existence / status is already known.  Subsequent
        # attempts for these users are skipped without network I/O.
        self.principal_unknown: set[str] = set()
        self.revoked_account: set[str] = set()
        self.wrong_realm: set[str] = set()

        # Users that triggered KRB_ERR_RESPONSE_TOO_BIG (UDP too small).
        self.response_too_big: set[str] = set()

        # Extracted from KRB_ERROR responses for clock-skew diagnostics.
        self.server_time: datetime.datetime | None = None

    def _display_user(self, user: str) -> str:
        """Return the KDC-corrected username if available, otherwise the original."""
        return self.username_corrections.get(user, user)

    # ===================================================================
    # Network transport
    # ===================================================================

    def _resolve_kdc(self, host: str) -> tuple[int, Any]:
        """Resolve *host* to an ``(address_family, sockaddr)`` pair.

        Raises :class:`ConnectionError` if DNS resolution fails.
        """
        try:
            af, _socktype, _proto, _canonname, sa = socket.getaddrinfo(host, _KDC_PORT, 0, socket.SOCK_STREAM)[0]
        except socket.gaierror as exc:
            msg = f"Cannot resolve KDC host {host} — {exc}"
            raise ConnectionError(msg) from exc
        return af, sa

    def _send_tcp(self, data: bytes, host: str) -> bytes:
        """Send *data* to the KDC over TCP and return the raw response."""
        af, sa = self._resolve_kdc(host)
        # TCP Kerberos frames are prefixed with a 4-byte big-endian length
        # (RFC 4120 §7.2.2 — unsigned 32-bit network-order).
        frame = struct.pack("!I", len(data)) + data
        sock = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.settimeout(self._timeout)
        try:
            sock.connect(sa)
            sock.sendall(frame)
            # Read the 4-byte length prefix, handling partial reads.
            header = self._recv_exact(sock, 4)
            # RFC 4120 §7.2.2: high bit is reserved and MUST be zero.
            recv_len = struct.unpack("!I", header)[0] & 0x7FFFFFFF
            result = self._recv_exact(sock, recv_len)
        except (OSError, struct.error, ValueError) as exc:
            msg = f"Cannot connect to KDC at {host}:{_KDC_PORT}/tcp — {exc}"
            raise ConnectionError(msg) from exc
        else:
            return result
        finally:
            sock.close()

    @staticmethod
    def _recv_exact(sock: socket.socket, length: int) -> bytes:
        """Read exactly *length* bytes from *sock*, raising on short read."""
        buf = bytearray()
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                msg = "Connection closed by KDC before full response was received"
                raise ConnectionError(msg)
            buf.extend(chunk)
        return bytes(buf)

    def _send_udp(self, data: bytes, host: str) -> bytes:
        """Send *data* to the KDC over UDP and return the raw response."""
        af, sa = self._resolve_kdc(host)
        sock = socket.socket(af, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(self._timeout)
        try:
            sock.connect(sa)
            sock.send(data)
            return sock.recv(8192)
        except OSError as exc:
            msg = f"Cannot connect to KDC at {host}:{_KDC_PORT}/udp — {exc}"
            raise ConnectionError(msg) from exc
        finally:
            sock.close()

    def _extract_server_time(self, raw_response: bytes) -> None:
        """Try to extract the KDC's clock from a KRB_ERROR response.

        The server timestamp is embedded as a ``GeneralizedTime`` field inside
        the error.  If present, it is saved to :attr:`server_time` so the
        caller can report clock-skew diagnostics.
        """
        try:
            for item in decoder.decode(raw_response):
                if isinstance(item, Sequence):
                    for component in vars(item)["_componentValues"]:
                        if isinstance(component, GeneralizedTime):
                            self.server_time = datetime.datetime.strptime(
                                component.asOctets().decode("utf-8"),
                                "%Y%m%d%H%M%SZ",
                            ).replace(tzinfo=datetime.UTC)
        except Exception:
            pass

    def _send_receive(self, data: bytes, host: str, kdc_host: str | None, transport: str, *, expect_preauth_required: bool = False) -> bytes:
        """Send a Kerberos message and return the raw response.

        Handles transport dispatch (TCP / UDP) and raises
        :class:`~impacket.krb5.kerberosv5.KerberosError` for any KRB_ERROR
        that the caller does not expect.

        When *expect_preauth_required* is True (salt retrieval), a
        ``KDC_ERR_PREAUTH_REQUIRED`` response is returned silently.
        When False (pre-auth), **all** KRB_ERROR responses are raised so
        the caller never mistakes an error for a successful AS-REP.
        """
        target = kdc_host if kdc_host is not None else host
        self.logger.debug(f"Sending to KDC at {target} via {transport.upper()}")

        if transport == "tcp":
            result = self._send_tcp(data, target)
        elif transport == "udp":
            result = self._send_udp(data, target)
        else:
            msg = f"Unknown transport protocol: {transport}"
            raise ValueError(msg)

        # Try to extract server time from any response (for clock-skew info).
        self._extract_server_time(result)

        # Check whether the response is a KRB_ERROR.
        try:
            krb_error = KerberosError(packet=decoder.decode(result, asn1Spec=KRB_ERROR())[0])
        except Exception:
            # Not a KRB_ERROR — likely an AS-REP (success).
            return result

        # During salt retrieval we intentionally trigger PREAUTH_REQUIRED
        # and want it returned silently.  For pre-auth requests, ALL errors
        # must be raised so the caller can distinguish success from failure.
        if expect_preauth_required and krb_error.getErrorCode() == _KDC_ERR_PREAUTH_REQUIRED:
            return result

        raise krb_error

    # ===================================================================
    # Salt retrieval  (AS-REQ without pre-auth — NOT a login attempt)
    # ===================================================================
    #
    # AES key derivation needs a salt that is specific to the user's
    # principal and realm.  The standard way to obtain it is to send an
    # AS-REQ with no pre-authentication data.  The KDC replies with
    # KDC_ERR_PREAUTH_REQUIRED and includes ETYPE-INFO2 (or ETYPE-INFO)
    # containing the salt for each supported encryption type.
    #
    # This request carries no password material and does NOT increment
    # the bad-password counter on the domain controller.

    def _get_salts(
        self,
        target: str,
        domain: str,
        user: str,
        etype: EncryptionType,
        transport: str,
    ) -> tuple[dict[int, bytes], dict[int, bytes | None]] | None:
        """Send a bare AS-REQ to retrieve the per-user salts.

        Returns ``(salts, s2kparams)`` or ``None`` on failure.
        Side-effects: may add *user* to :attr:`principal_unknown`
        or :attr:`revoked_account`.
        """
        self.logger.debug(f"Retrieving Kerberos salts for {user}")

        domain_upper = domain.upper()
        as_req = self._build_bare_as_req(domain_upper, user, (_ETYPE_MAP[etype],))

        try:
            response = self._send_receive(data=encoder.encode(as_req), host=domain, kdc_host=target, transport=transport, expect_preauth_required=True)
        except ConnectionError as exc:
            self.logger.error(str(exc))
            return None
        except Exception as exc:
            return self._handle_salt_error(user, exc)

        # If the response is an AS-REP rather than KRB_ERROR, the user has
        # pre-auth disabled (ASREProastable).  There is no e-data with salts,
        # so synthesise a default salt: REALM + username (RFC 4120 §5.2.7.4).
        is_as_rep = False
        try:
            decoder.decode(response, asn1Spec=AS_REP())[0]
            is_as_rep = True
        except Exception:
            pass
        if is_as_rep:
            self.logger.debug(f"User {user} — no pre-auth required (ASREProastable), using default salt")
            default_salt = (domain_upper + user).encode()
            enc_type = _ETYPE_MAP[etype]
            return {enc_type: default_salt}, {}

        salts, s2kparams = self._parse_salt_response(response, domain_upper, user)
        return salts, s2kparams

    def _build_bare_as_req(self, realm: str, user: str, etypes: tuple[int, ...]) -> AS_REQ:
        """Build an AS-REQ with no pre-authentication data.

        Used for salt retrieval — the KDC responds with
        ``KDC_ERR_PREAUTH_REQUIRED`` and the salt in the error's e-data.
        """
        if realm == "":
            msg = "Empty domain not allowed in Kerberos"
            raise ValueError(msg)

        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = _AS_REQ_TAG

        req_body = seq_set(as_req, "req-body")
        req_body["kdc-options"] = constants.encodeFlags(_KDC_OPTS)
        seq_set(req_body, "sname", Principal(f"krbtgt/{realm}", type=_NT_SRV_INST).components_to_asn1)
        seq_set(req_body, "cname", Principal(user, type=_NT_PRINCIPAL).components_to_asn1)
        req_body["realm"] = realm

        future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        req_body["till"] = KerberosTime.to_asn1(future)
        req_body["rtime"] = KerberosTime.to_asn1(future)
        req_body["nonce"] = secrets.randbits(31)
        seq_set_iter(req_body, "etype", etypes)

        return as_req

    def _handle_salt_error(self, user: str, exc: Exception) -> None:
        """Interpret errors from the salt-retrieval AS-REQ.

        These errors occur during the bare AS-REQ (no pre-auth data) sent
        to retrieve the per-user AES salt.  Only a subset of KDC errors
        can appear here because no authentication is attempted.
        """
        err = str(exc)

        # -- user does not exist in AD ---
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
            self.logger.debug(f"User {user} — KDC_ERR_C_PRINCIPAL_UNKNOWN (not found in AD)")
            self.principal_unknown.add(user)

        # -- account revoked (disabled / expired / locked out) ---
        elif "KDC_ERR_CLIENT_REVOKED" in err:
            self.logger.debug(f"User {user} — KDC_ERR_CLIENT_REVOKED (account disabled, expired, locked out, or outside logon hours)")
            self.revoked_account.add(user)

        # -- AD entry expired (distinct from CLIENT_REVOKED) ---
        elif "KDC_ERR_NAME_EXP" in err:
            self.logger.debug(f"User {user} — KDC_ERR_NAME_EXP (account entry expired in AD)")
            self.revoked_account.add(user)

        # -- account not yet valid (future start date in AD) ---
        elif "KDC_ERR_CLIENT_NOTYET" in err:
            self.logger.debug(f"User {user} — KDC_ERR_CLIENT_NOTYET (account not yet valid)")
            self.revoked_account.add(user)

        # -- null key (no password set on account) ---
        elif "KDC_ERR_NULL_KEY" in err:
            self.logger.debug(f"User {user} — KDC_ERR_NULL_KEY (no key set — password may need reset)")
            self.revoked_account.add(user)

        # -- encryption type not supported ---
        elif "KDC_ERR_ETYPE_NOSUPP" in err:
            self.logger.debug(f"User {user} — KDC_ERR_ETYPE_NOSUPP (encryption type not supported for salt retrieval)")

        # -- response too big for UDP ---
        elif "KRB_ERR_RESPONSE_TOO_BIG" in err:
            self.logger.debug(f"User {user} — KRB_ERR_RESPONSE_TOO_BIG (retry with --transport tcp)")
            self.response_too_big.add(user)

        # -- wrong realm (cross-realm TGT to wrong domain, typically misconfigured DNS) ---
        elif "KDC_ERR_WRONG_REALM" in err:
            self.logger.debug(f"User {user} — KDC_ERR_WRONG_REALM (incorrect domain or principal)")
            self.wrong_realm.add(user)

        # -- policy rejects request (logon restrictions: workstation, time, smart card) ---
        elif "KDC_ERR_POLICY" in err:
            self.logger.debug(f"User {user} — KDC_ERR_POLICY (logon restricted by policy — typically smart card required)")

        else:
            self.logger.debug(f"Salt retrieval error for {user}: {exc}")

    def _parse_salt_response(self, response: bytes, realm: str = "", user: str = "") -> tuple[dict[int, bytes], dict[int, bytes | None]]:
        """Extract salts and s2kparams from a KDC_ERR_PREAUTH_REQUIRED response.

        Returns ``(salts, s2kparams)`` where *salts* is ``{etype_int: salt_bytes}``
        and *s2kparams* is ``{etype_int: params_bytes_or_None}``.

        As a side-effect, attempts to extract the correct username casing
        from the AES salt (format: ``REALMusername``) and stores it in
        :attr:`username_corrections`.
        """
        try:
            try:
                as_rep = decoder.decode(response, asn1Spec=KRB_ERROR())[0]
            except Exception:
                as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]

            result: dict[int, bytes] = {}
            s2kparams: dict[int, bytes | None] = {}
            found_etype_info2 = False
            methods = decoder.decode(as_rep["e-data"], asn1Spec=METHOD_DATA())[0]
            for method in methods:
                padata_type = int(method["padata-type"])

                # ETYPE-INFO2 is the modern salt format (RFC 4120 §5.2.7.5).
                # Per the RFC, ETYPE-INFO2 takes priority over ETYPE-INFO;
                # if ETYPE-INFO2 is present, ETYPE-INFO SHOULD be ignored.
                if padata_type == _PA_ETYPE_INFO2:
                    found_etype_info2 = True
                    for entry in decoder.decode(method["padata-value"], asn1Spec=ETYPE_INFO2())[0]:
                        try:
                            salt = "" if entry["salt"] is None or not entry["salt"].hasValue() else entry["salt"].prettyPrint()
                        except PyAsn1Error:
                            salt = ""
                        etype_val = int(entry["etype"])
                        result[etype_val] = salt.encode()
                        # Extract s2kparams if present (RFC 4120 §5.2.7.5).
                        # Used as the opaque parameter to string-to-key
                        # (e.g., PBKDF2 iteration count for AES per RFC 3962).
                        try:
                            if entry["s2kparams"] is not None and entry["s2kparams"].hasValue():
                                s2kparams[etype_val] = bytes(entry["s2kparams"])
                        except PyAsn1Error:
                            pass
                        # Try to extract the correct username case from the salt.
                        if salt and realm and user and salt.startswith(realm):
                            correct_user = salt[len(realm) :]
                            if correct_user and correct_user.lower() == user.lower() and correct_user != user:
                                self.username_corrections[user] = correct_user
                                self.logger.debug(f"Username case correction: {user} → {correct_user}")

                # ETYPE-INFO is the legacy format; only used as a fallback
                # when ETYPE-INFO2 was not present (RFC 4120 §5.2.7.5).
                elif padata_type == _PA_ETYPE_INFO and not found_etype_info2:
                    for entry in decoder.decode(method["padata-value"], asn1Spec=ETYPE_INFO())[0]:
                        try:
                            # ETYPE-INFO salt is OCTET STRING (RFC 4120 §5.2.7.4);
                            # extract raw bytes, not prettyPrint() which may hex-format.
                            if entry["salt"] is None or not entry["salt"].hasValue():
                                salt_bytes = b""
                            else:
                                salt_bytes = bytes(entry["salt"])
                        except PyAsn1Error:
                            salt_bytes = b""
                        result[int(entry["etype"])] = salt_bytes

        except Exception:
            self.logger.debug("Failed to parse salt response")
            return {}, {}
        else:
            return result, s2kparams

    # ===================================================================
    # Key derivation
    # ===================================================================

    def _derive_key(
        self,
        *,
        target: str,
        domain: str,
        user: str,
        password: str | None,
        rc4_key: str | None,
        aes128_key: str | None,
        aes256_key: str | None,
        etype: EncryptionType,
        transport: str,
    ) -> tuple[Any, Key] | None:
        """Derive a ``(cipher, Key)`` from the supplied credential material.

        Key selection priority (highest wins):

        1. AES256 raw key
        2. AES128 raw key
        3. RC4 raw key
        4. Password → key (RC4 via NT-hash, AES via salt + string-to-key)

        Returns ``None`` if key derivation fails (e.g. cannot retrieve salt).
        """
        # -- raw key (no KDC interaction needed) ----------------------------
        aes256_bytes = self._try_unhex(aes256_key)
        aes128_bytes = self._try_unhex(aes128_key)
        rc4_bytes = self._try_unhex(rc4_key)

        if aes256_bytes:
            enc_type = _ETYPE_MAP[EncryptionType.AES256]
            cipher = _enctype_table[enc_type]
            return cipher, Key(cipher.enctype, aes256_bytes)

        if aes128_bytes:
            enc_type = _ETYPE_MAP[EncryptionType.AES128]
            cipher = _enctype_table[enc_type]
            return cipher, Key(cipher.enctype, aes128_bytes)

        if rc4_bytes:
            enc_type = _ETYPE_MAP[EncryptionType.RC4]
            cipher = _enctype_table[enc_type]
            return cipher, Key(cipher.enctype, rc4_bytes)

        # -- password-based key derivation ----------------------------------
        enc_type = _ETYPE_MAP[etype]
        cipher = _enctype_table[enc_type]

        if etype == EncryptionType.RC4:
            # RC4 key = NT hash of the password.  No salt needed.
            return cipher, Key(cipher.enctype, compute_nthash(password or ""))

        # AES needs a per-user salt from the KDC (cached after first fetch).
        salts = self._get_or_cache_salts(target=target, domain=domain, user=user, etype=etype, transport=transport)
        if salts is None:
            return None

        if enc_type not in salts:
            self.logger.debug(f"No salt available for {self._display_user(user)} etype {enc_type}")
            return None

        self.logger.debug(f"Using salt for {self._display_user(user)}: {salts[enc_type].decode('utf-8', errors='replace')}")
        # Use s2kparams from ETYPE-INFO2 if available (RFC 4120 §5.2.7.5).
        params = self.s2kparams.get(user, {}).get(enc_type)
        return cipher, cipher.string_to_key(password or "", salts[enc_type], params)

    def _get_or_cache_salts(
        self,
        *,
        target: str,
        domain: str,
        user: str,
        etype: EncryptionType,
        transport: str,
    ) -> dict[int, bytes] | None:
        """Return cached salts for *user*, fetching from the KDC if needed."""
        if user in self.salts:
            return self.salts[user]

        fetched = self._get_salts(target=target, domain=domain, user=user, etype=etype, transport=transport)

        # The salt request may have revealed that the user is unknown/revoked/wrong-realm.
        if user in self.principal_unknown or user in self.revoked_account or user in self.wrong_realm:
            return None
        if not fetched or not fetched[0]:
            self.logger.debug(f"Could not get salts for {self._display_user(user)}")
            return None

        salts, s2k = fetched
        self.salts[user] = salts
        if s2k:
            self.s2kparams[user] = s2k
        return salts

    @staticmethod
    def _try_unhex(hex_str: str | None) -> bytes | None:
        """Convert a hex string to bytes, returning ``None`` on failure."""
        if not hex_str:
            return None
        try:
            return unhexlify(hex_str)
        except (ValueError, binascii.Error):
            return None

    # ===================================================================
    # Pre-authentication  (AS-REQ with encrypted timestamp — login attempt)
    # ===================================================================
    #
    # This is the actual authentication step.  The client proves knowledge
    # of the user's key by encrypting the current timestamp with it.  The
    # KDC decrypts the timestamp; if it succeeds and the timestamp is
    # within the allowed skew window, the KDC returns an AS-REP (TGT).
    #
    # A WRONG key here → KDC_ERR_PREAUTH_FAILED → bad-password counter += 1.

    def pre_authentication(
        self,
        target: str,
        domain: str,
        user: str,
        password: str | None,
        rc4_key: str | None,
        aes128_key: str | None,
        aes256_key: str | None,
        etype: EncryptionType,
        transport: str,
    ) -> AuthResult:
        """Attempt Kerberos pre-authentication for *user*.

        Sends a single AS-REQ containing an encrypted timestamp (PA-ENC-
        TIMESTAMP).  If the KDC returns an AS-REP, the credential is valid.
        """
        if user in self.principal_unknown or user in self.wrong_realm:
            return AuthResult(success=False)
        if user in self.revoked_account:
            return AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED")

        # Step 1: Derive the encryption key from the supplied credential.
        derived = self._derive_key(
            target=target,
            domain=domain,
            user=user,
            password=password,
            rc4_key=rc4_key,
            aes128_key=aes128_key,
            aes256_key=aes256_key,
            etype=etype,
            transport=transport,
        )
        if derived is None:
            # Key derivation failed (e.g. user unknown, salt unavailable).
            if user in self.principal_unknown or user in self.wrong_realm:
                return AuthResult(success=False)
            if user in self.revoked_account:
                return AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED")
            return AuthResult(success=False)
        cipher, key = derived

        # Step 2: Build the AS-REQ with an encrypted timestamp as pre-auth.
        # Use the corrected username casing if available (extracted from salt).
        effective_user = self.username_corrections.get(user, user)
        as_req = self._build_preauth_as_req(domain.upper(), effective_user, cipher, key)

        # Step 3: Send and interpret the response.
        return self._send_preauth_request(as_req, domain, user, transport, target)

    def _build_preauth_as_req(self, realm: str, user: str, cipher: Any, key: Key) -> AS_REQ:
        """Build an AS-REQ with PA-ENC-TIMESTAMP pre-authentication data."""
        # Encrypt the current timestamp with the user's key.
        timestamp = PA_ENC_TS_ENC()
        now = datetime.datetime.now(datetime.UTC)
        timestamp["patimestamp"] = KerberosTime.to_asn1(now)
        timestamp["pausec"] = now.microsecond

        encrypted_ts = cipher.encrypt(key, 1, encoder.encode(timestamp), None)

        enc_data = EncryptedData()
        enc_data["etype"] = cipher.enctype
        enc_data["cipher"] = encrypted_ts

        # Assemble the AS-REQ with the pre-auth payload.
        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = _AS_REQ_TAG
        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = _PA_ENC_TIMESTAMP
        as_req["padata"][0]["padata-value"] = encoder.encode(enc_data)

        req_body = seq_set(as_req, "req-body")
        req_body["kdc-options"] = constants.encodeFlags(_KDC_OPTS)
        seq_set(req_body, "sname", Principal(f"krbtgt/{realm}", type=_NT_SRV_INST).components_to_asn1)
        seq_set(req_body, "cname", Principal(user, type=_NT_PRINCIPAL).components_to_asn1)
        req_body["realm"] = realm

        future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        req_body["till"] = KerberosTime.to_asn1(future)
        req_body["rtime"] = KerberosTime.to_asn1(future)
        req_body["nonce"] = secrets.randbits(31)
        seq_set_iter(req_body, "etype", (int(cipher.enctype),))

        return as_req

    def _send_preauth_request(self, as_req: Any, domain: str, user: str, transport: str, target: str) -> AuthResult:
        """Send a pre-auth AS-REQ and interpret the KDC's response."""
        try:
            tgt = self._send_receive(data=encoder.encode(as_req), host=domain, kdc_host=target, transport=transport)
            if tgt is not None:
                return AuthResult(success=True)
        except ConnectionError as exc:
            self.logger.error(str(exc))
            return AuthResult(success=False, details="connection failed")
        except Exception as exc:
            return self._handle_preauth_error(user, exc)

        return AuthResult(success=False)

    def _handle_preauth_error(self, user: str, exc: Exception) -> AuthResult:
        """Map a KDC error from the pre-auth AS-REQ to an AuthResult.

        Error handling is ordered by likelihood during a credential spray
        against a Windows AD KDC.  Messages reference the AD-specific
        meaning of each error code per MS-KILE and Microsoft docs.
        """
        err = str(exc)
        dname = self._display_user(user)

        # -- wrong password / key (0x18) ---
        # The encrypted timestamp could not be decrypted.
        if "KDC_ERR_PREAUTH_FAILED" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_PREAUTH_FAILED (wrong password or key)")
            return AuthResult(success=False)

        # -- account revoked: disabled, expired, or locked out (0x12) ---
        # AD returns this for any of: account disabled, account expired,
        # or account locked out.  The error code does not distinguish.
        if "KDC_ERR_CLIENT_REVOKED" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_CLIENT_REVOKED (account disabled, expired, locked out, or outside logon hours)")
            self.revoked_account.add(user)
            return AuthResult(success=False, details="KDC_ERR_CLIENT_REVOKED")

        # -- password expired (0x17) ---
        # The password IS correct, but the account requires a password
        # change.  This confirms the credential is valid.
        if "KDC_ERR_KEY_EXPIRED" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_KEY_EXPIRED (password correct but expired — must change)")
            return AuthResult(success=True, details="KDC_ERR_KEY_EXPIRED")

        # -- clock skew (0x25) ---
        # Timestamp in the pre-auth data differs from KDC time by more
        # than the allowed skew (default 5 minutes in AD).  All Kerberos
        # results are unreliable until clocks are synced.
        if "KRB_AP_ERR_SKEW" in err:
            self.logger.debug(f"User {dname} — KRB_AP_ERR_SKEW (clock skew too great)")
            return AuthResult(success=False, details="KRB_AP_ERR_SKEW")

        # -- response too big for UDP (0x34) ---
        # The AS-REP exceeds the UDP datagram size.  Retry with TCP.
        if "KRB_ERR_RESPONSE_TOO_BIG" in err:
            self.logger.debug(f"User {dname} — KRB_ERR_RESPONSE_TOO_BIG (retry with --transport tcp)")
            self.response_too_big.add(user)
            return AuthResult(success=False, details="KRB_ERR_RESPONSE_TOO_BIG")

        # -- user does not exist (0x6) ---
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_C_PRINCIPAL_UNKNOWN (user not found in AD)")
            self.principal_unknown.add(user)
            return AuthResult(success=False)

        # -- policy rejects logon (0xC) ---
        # Workstation restriction, smart card required, logon hours, etc.
        # The password may or may not be correct — AD blocks the attempt
        # before checking the credential.
        if "KDC_ERR_POLICY" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_POLICY (logon restricted by AD policy — typically smart card required)")
            return AuthResult(success=None, details="KDC_ERR_POLICY")

        # -- encryption type not supported (0xE) ---
        if "KDC_ERR_ETYPE_NOSUPP" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_ETYPE_NOSUPP (encryption type not supported)")
            return AuthResult(success=False, details="KDC_ERR_ETYPE_NOSUPP")

        # -- AD entry expired (0x1) ---
        if "KDC_ERR_NAME_EXP" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_NAME_EXP (account entry expired in AD)")
            self.revoked_account.add(user)
            return AuthResult(success=False, details="KDC_ERR_NAME_EXP")

        # -- account not yet valid (0x15) ---
        if "KDC_ERR_CLIENT_NOTYET" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_CLIENT_NOTYET (account not yet valid — future start date)")
            self.revoked_account.add(user)
            return AuthResult(success=False, details="KDC_ERR_CLIENT_NOTYET")

        # -- null key (0x9) ---
        # Account has no key material.  Admin must reset the password.
        if "KDC_ERR_NULL_KEY" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_NULL_KEY (no key set on account — password may need reset)")
            self.revoked_account.add(user)
            return AuthResult(success=False, details="KDC_ERR_NULL_KEY")

        # -- wrong realm (0x44) ---
        # Cross-realm TGT presented to wrong domain, typically misconfigured DNS.
        if "KDC_ERR_WRONG_REALM" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_WRONG_REALM (incorrect domain or principal)")
            self.wrong_realm.add(user)
            return AuthResult(success=False)

        # -- smart card / PKINIT errors (0x3E-0x42) ---
        if "KDC_ERR_CLIENT_NOT_TRUSTED" in err:
            self.logger.debug(f"User {dname} — KDC_ERR_CLIENT_NOT_TRUSTED (smart card certificate revoked or untrusted CA)")
            return AuthResult(success=False)

        # -- generic error (0x3C) ---
        # PAC too large, SPN issues, crypto subsystem errors, etc.
        if "KRB_ERR_GENERIC" in err:
            self.logger.debug(f"User {dname} — KRB_ERR_GENERIC (generic KDC error)")
            return AuthResult(success=False)

        # -- anything else: log the raw error ---
        self.logger.debug(f"User {dname} — Kerberos error: {exc}")
        return AuthResult(success=False)

    # ===================================================================
    # Username enumeration  (bare AS-REQ — NOT a login attempt)
    # ===================================================================

    def enumerate_user(
        self,
        target: str,
        domain: str,
        user: str,
        transport: str,
    ) -> AuthResult:
        """Enumerate whether *user* exists in AD via a bare AS-REQ.

        Sends an AS-REQ with no pre-authentication data using all three
        encryption types (AES256, AES128, RC4) to maximize compatibility.
        The KDC response reveals whether the user exists:

        - ``KDC_ERR_PREAUTH_REQUIRED`` → user exists (normal account)
        - ``AS-REP`` → user exists and is ASREProastable (no pre-auth required)
        - ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` → user does not exist
        - ``KDC_ERR_CLIENT_REVOKED`` → user exists but is revoked

        This does **not** cause a login attempt and does **not** increment
        the bad-password counter.
        """
        domain_upper = domain.upper()
        etypes = (
            _ETYPE_MAP[EncryptionType.AES256],
            _ETYPE_MAP[EncryptionType.AES128],
            _ETYPE_MAP[EncryptionType.RC4],
        )
        as_req = self._build_bare_as_req(domain_upper, user, etypes)

        try:
            response = self._send_receive(
                data=encoder.encode(as_req),
                host=domain,
                kdc_host=target,
                transport=transport,
                expect_preauth_required=True,
            )
        except ConnectionError as exc:
            self.logger.error(str(exc))
            return AuthResult(success=False, details="connection failed")
        except Exception as exc:
            return self._handle_enum_error(user, exc)

        # _send_receive returns without raising for two cases:
        # 1. KDC_ERR_PREAUTH_REQUIRED (the expected "user exists" response)
        # 2. AS-REP (user exists and has pre-auth disabled — ASREProastable)
        try:
            decoder.decode(response, asn1Spec=KRB_ERROR())[0]
            # Successfully decoded as KRB_ERROR → PREAUTH_REQUIRED (user exists)
            return AuthResult(success=True)
        except Exception:
            # Not a KRB_ERROR → likely an AS-REP (ASREProastable)
            try:
                decoder.decode(response, asn1Spec=AS_REP())[0]
                return AuthResult(success=True, details="no_preauth")
            except Exception:
                # Unexpected response format — treat as exists (we got a response)
                return AuthResult(success=True)

    @staticmethod
    def _extract_krb_error_name(exc: Exception) -> str:
        """Extract the Kerberos error code name from an Impacket exception.

        Returns the RFC error name (e.g. ``"KDC_ERR_CLIENT_REVOKED"``) or
        the raw exception string if no known code is found.
        """
        err = str(exc)
        for error_code in cast("Any", constants.ErrorCodes):
            if error_code.name in err:
                return error_code.name
        return err

    def _handle_enum_error(self, user: str, exc: Exception) -> AuthResult:
        """Interpret errors from the enumeration bare AS-REQ.

        Only ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` definitively means the user
        does not exist.  Protocol-level errors (SKEW, RESPONSE_TOO_BIG)
        are indeterminate.  Any other KDC error confirms the user exists
        because the KDC looked up the principal before returning the error.
        The raw error name is passed through in ``details``.
        """
        err = str(exc)
        code_name = self._extract_krb_error_name(exc)

        # -- definitively does not exist (0x6) ---
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
            self.principal_unknown.add(user)
            return AuthResult(success=False)

        # -- clock skew (0x25) — protocol error, not a user-existence signal ---
        if "KRB_AP_ERR_SKEW" in err:
            return AuthResult(success=False, details="KRB_AP_ERR_SKEW")

        # -- response too big (0x34) — protocol error, retry with TCP ---
        if "KRB_ERR_RESPONSE_TOO_BIG" in err:
            self.response_too_big.add(user)
            return AuthResult(success=False, details="KRB_ERR_RESPONSE_TOO_BIG")

        # -- wrong realm (0x44) — domain mismatch ---
        if "KDC_ERR_WRONG_REALM" in err:
            self.wrong_realm.add(user)
            return AuthResult(success=False, details=code_name)

        # -- any other error: the KDC looked up the principal and returned
        # a specific error about it, which confirms the user exists.
        # Pass the raw error name through so the caller can display it.
        return AuthResult(success=True, details=code_name)

    # ===================================================================
    # Ticket validation  (ccache / kirbi — NOT a login attempt)
    # ===================================================================
    #
    # A ticket file (.ccache or .kirbi) contains a TGT obtained from a
    # prior authentication.  To validate it, credwolf sends a TGS-REQ
    # using the TGT — if the KDC issues a service ticket, the TGT is
    # still valid.  This does not touch the bad-password counter.

    @staticmethod
    def detect_ticket_format(path: str) -> str:
        """Detect whether *path* is a ccache or kirbi file by its magic byte.

        Returns ``"ccache"`` or ``"kirbi"``.  Raises :class:`ValueError` if
        the format cannot be determined.
        """
        with Path(path).open("rb") as fh:
            header = fh.read(1)
        if not header:
            msg = f"Empty ticket file: {path}"
            raise ValueError(msg)
        magic = struct.unpack(">B", header)[0]
        if magic == _CCACHE_MAGIC:
            return "ccache"
        if magic == _KIRBI_MAGIC:
            return "kirbi"
        msg = f"Unrecognised ticket format (magic byte 0x{magic:02x}): {path}"
        raise ValueError(msg)

    def _load_ticket(self, path: str) -> tuple[CCache, str]:
        """Load a ticket file, auto-detecting ccache vs kirbi format.

        Both formats are converted to Impacket's :class:`CCache` object,
        which provides a uniform interface for credential extraction.
        """
        fmt = self.detect_ticket_format(path)
        if fmt == "kirbi":
            return CCache.loadKirbiFile(path), "kirbi"
        return CCache.loadFile(path), "ccache"

    def ticket_authentication(
        self,
        ticket_path: str,
        domain: str,
        user: str,
        kdc_ip: str | None,
    ) -> tuple[AuthResult, str]:
        """Validate a ticket file's TGT by requesting a TGS from the KDC.

        Returns ``(result, format)`` where *format* is ``"ccache"`` or
        ``"kirbi"``.
        """
        # Load and auto-detect format.
        try:
            ticket_cache, fmt = self._load_ticket(ticket_path)
        except (ValueError, OSError) as exc:
            self.logger.error(f"Failed to load ticket: {exc}")
            return AuthResult(success=False, details="invalid ticket"), "ticket"
        except Exception:
            self.logger.error(f"Failed to load ticket: {ticket_path}")
            return AuthResult(success=False, details="invalid ticket"), "ticket"

        # Find the TGT credential inside the cache.
        domain_upper = domain.upper()
        tgt_principal = f"krbtgt/{domain_upper}@{domain_upper}"
        creds = ticket_cache.getCredential(tgt_principal)
        if creds is None:
            self.logger.debug(f"No TGT found in ticket for {domain}")
            return AuthResult(success=False, details="no TGT in ticket"), fmt

        # Verify that the ticket belongs to the expected user.
        ticket_user = ""
        try:
            ticket_user = creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
        except Exception:
            try:
                if ticket_cache.principal is not None and len(ticket_cache.principal.components) > 0:
                    ticket_user = ticket_cache.principal.components[0]["data"].decode("utf-8", errors="replace")
            except Exception:
                self.logger.debug("Could not extract principal from ticket")

        if ticket_user.lower() != user.lower():
            self.logger.debug(f"Ticket principal {ticket_user} does not match user {self._display_user(user)}")
            return AuthResult(success=False, details="principal mismatch"), fmt

        # Send a TGS-REQ to confirm the TGT is still accepted by the KDC.
        tgt = creds.toTGT()
        server_name = Principal(f"krbtgt/{domain_upper}", type=_NT_SRV_INST)
        try:
            getKerberosTGS(
                serverName=server_name,
                domain=domain,
                kdcHost=kdc_ip,
                tgt=tgt["KDC_REP"],
                cipher=tgt["cipher"],
                sessionKey=tgt["sessionKey"],
            )
            return AuthResult(success=True), fmt
        except Exception:
            self.logger.debug(f"Ticket TGS validation failed for {self._display_user(user)}")
            return AuthResult(success=False), fmt
