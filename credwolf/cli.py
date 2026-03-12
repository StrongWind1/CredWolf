"""Command-line interface for credwolf."""

from __future__ import annotations

import argparse
import contextlib
from pathlib import Path

from credwolf import __version__
from credwolf.attack import AttackRunner
from credwolf.log import Logger
from credwolf.models import (
    AttackOptions,
    EncryptionType,
    NtlmTransport,
    Protocol,
    TransportProtocol,
)


def _build_parser() -> tuple[
    argparse.ArgumentParser,
    argparse.ArgumentParser,
    argparse.ArgumentParser,
    argparse.ArgumentParser,
]:
    """Construct the argument parser tree.

    Returns the root parser plus references to the *ntlm*, *kerberos*,
    and *userenum* sub-parsers so validation errors can print targeted help.
    """
    description = "Credential validation tool for Active Directory Domain Services."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="count",
        default=0,
        help="verbosity level (-v verbose, -vv debug, -vvv trace)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-d",
        "--domain",
        dest="domain",
        required=True,
        help="domain name (required)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        help="write results to file",
    )
    parser.add_argument(
        "--stop-on-success",
        dest="stop_on_success",
        action="store_true",
        help="stop on first valid authentication",
    )
    parser.add_argument(
        "--delay",
        dest="delay",
        type=float,
        default=0,
        help="seconds to wait between attempts (default: 0)",
    )
    parser.add_argument(
        "--jitter",
        dest="jitter",
        type=float,
        default=0,
        help="random jitter +/- seconds added to delay (default: 0)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=15,
        help="connection timeout in seconds; 0 for no timeout (default: 15)",
    )
    parser.add_argument(
        "--max-lockouts",
        dest="max_lockouts",
        type=int,
        default=0,
        help="stop after N consecutive revoked accounts (disabled/expired/locked); 0 to disable (default: 0)",
    )

    # -- protocol subcommands -----------------------------------------------
    proto_sub = parser.add_subparsers(dest="protocol", help="authentication protocol")

    # --- NTLM --------------------------------------------------------------
    ntlm_parser = proto_sub.add_parser(
        "ntlm",
        help="NTLM credential validation (over SMB, LDAP, or LDAPS)",
    )

    ntlm_user_group = ntlm_parser.add_argument_group("user source (mutually exclusive)")
    ntlm_user_mx = ntlm_user_group.add_mutually_exclusive_group()
    ntlm_user_mx.add_argument("-u", "--user", dest="user", help="single username")
    ntlm_user_mx.add_argument("-U", "--users-file", dest="users_file", help="username list file")

    ntlm_secret_group = ntlm_parser.add_argument_group("secret source (mutually exclusive)")
    ntlm_secret_mx = ntlm_secret_group.add_mutually_exclusive_group()
    ntlm_secret_mx.add_argument("-p", "--password", dest="password", help="single password")
    ntlm_secret_mx.add_argument("-P", "--passwords-file", dest="passwords_file", help="password list file")
    ntlm_secret_mx.add_argument(
        "-H",
        "--hashes-file",
        dest="hashes_file",
        help="hash list file (NT hash or LM:NT pair per line)",
    )
    ntlm_secret_mx.add_argument(
        "--user-pass-file",
        dest="user_pass_file",
        help="colon-separated user:password file",
    )
    ntlm_secret_mx.add_argument(
        "--hash",
        dest="hash_value",
        help="single hash (NT or LM:NT format)",
    )
    ntlm_secret_mx.add_argument(
        "--user-hash-file",
        dest="user_hash_file",
        help="colon-separated user:hash file (NT or LM:NT)",
    )

    ntlm_target_group = ntlm_parser.add_argument_group("target")
    ntlm_target_group.add_argument("--dc-ip", dest="dc_ip", required=True, help="domain controller IP (required)")

    ntlm_parser.add_argument(
        "--transport",
        dest="ntlm_transport",
        choices=["smb", "ldap", "ldaps"],
        default="smb",
        help="transport protocol (default: smb)",
    )

    # --- Kerberos ----------------------------------------------------------
    kerberos_parser = proto_sub.add_parser(
        "kerberos",
        help="Kerberos credential validation (over UDP or TCP)",
    )

    kerb_user_group = kerberos_parser.add_argument_group("user source (mutually exclusive)")
    kerb_user_mx = kerb_user_group.add_mutually_exclusive_group()
    kerb_user_mx.add_argument("-u", "--user", dest="user", help="single username")
    kerb_user_mx.add_argument("-U", "--users-file", dest="users_file", help="username list file")

    kerb_secret_group = kerberos_parser.add_argument_group("secret source")
    kerb_secret_group.add_argument("-p", "--password", dest="password", help="single password")
    kerb_secret_group.add_argument("-P", "--passwords-file", dest="passwords_file", help="password list file")
    kerb_secret_group.add_argument("--rc4-file", dest="rc4_file", help="RC4/NT hash list file")
    kerb_secret_group.add_argument(
        "--aes128-file",
        dest="aes128_file",
        help="AES128 key list file",
    )
    kerb_secret_group.add_argument(
        "--aes256-file",
        dest="aes256_file",
        help="AES256 key list file",
    )
    kerb_secret_group.add_argument("--rc4-key", dest="rc4_key", help="single RC4/NT key (32 hex chars)")
    kerb_secret_group.add_argument("--aes128-key", dest="aes128_key", help="single AES128 key (32 hex chars)")
    kerb_secret_group.add_argument("--aes256-key", dest="aes256_key", help="single AES256 key (64 hex chars)")
    kerb_secret_group.add_argument("--ticket", dest="ticket", help="ticket file containing TGT (.ccache or .kirbi)")
    kerb_secret_group.add_argument(
        "--user-key-file",
        dest="user_key_file",
        help="colon-separated user:key file — auto-detects RC4 (32 hex) vs AES256 (64 hex); use --etype aes128 to treat 32-hex keys as AES128",
    )

    kerb_target_group = kerberos_parser.add_argument_group("target")
    kerb_target_group.add_argument("--kdc-ip", dest="kdc_ip", required=True, help="KDC IP address (required)")

    kerberos_parser.add_argument(
        "--transport",
        dest="kdc_transport",
        choices=["tcp", "udp"],
        default="udp",
        help="transport protocol (default: udp)",
    )
    kerberos_parser.add_argument(
        "-e",
        "--etype",
        dest="etype",
        choices=["rc4", "aes128", "aes256"],
        default="rc4",
        help="encryption type for password auth and --user-key-file 32-hex disambiguation (default: rc4)",
    )

    # --- Username enumeration -----------------------------------------------
    userenum_parser = proto_sub.add_parser(
        "userenum",
        help="Username enumeration via Kerberos (bare AS-REQ, no login attempt)",
    )

    ue_user_group = userenum_parser.add_argument_group("user source (mutually exclusive)")
    ue_user_mx = ue_user_group.add_mutually_exclusive_group()
    ue_user_mx.add_argument("-u", "--user", dest="user", help="single username")
    ue_user_mx.add_argument("-U", "--users-file", dest="users_file", help="username list file")

    ue_target_group = userenum_parser.add_argument_group("target")
    ue_target_group.add_argument("--kdc-ip", dest="kdc_ip", required=True, help="KDC IP address (required)")

    userenum_parser.add_argument(
        "--transport",
        dest="kdc_transport",
        choices=["tcp", "udp"],
        default="udp",
        help="transport protocol (default: udp)",
    )

    return parser, ntlm_parser, kerberos_parser, userenum_parser


def _validate(
    ns: argparse.Namespace,
    parser: argparse.ArgumentParser,
    ntlm_parser: argparse.ArgumentParser,
    kerberos_parser: argparse.ArgumentParser,
    userenum_parser: argparse.ArgumentParser,
) -> None:
    """Validate parsed arguments and exit with an error if invalid."""
    if ns.protocol is None:
        parser.error("choose a protocol: credwolf ntlm ... | credwolf kerberos ...")

    if ns.protocol == "ntlm":
        _validate_ntlm(ns, ntlm_parser)
    elif ns.protocol == "kerberos":
        _validate_kerberos(ns, kerberos_parser)
    elif ns.protocol == "userenum":
        _validate_userenum(ns, userenum_parser)


def _validate_ntlm(ns: argparse.Namespace, p: argparse.ArgumentParser) -> None:
    has_colon = getattr(ns, "user_pass_file", None) or getattr(ns, "user_hash_file", None)
    has_user = getattr(ns, "user", None) or getattr(ns, "users_file", None)
    has_secret = getattr(ns, "password", None) is not None or getattr(ns, "passwords_file", None) or getattr(ns, "hashes_file", None) or getattr(ns, "hash_value", None)

    if has_colon:
        if has_user or has_secret:
            p.error(
                "--user-pass-file / --user-hash-file cannot be combined with -u/--user, -U/--users-file, -p/--password, -P/--passwords-file, -H/--hashes-file, or --hash",
            )
    elif not has_user:
        p.error("one of -u/--user or -U/--users-file is required")
    elif not has_secret:
        p.error("one of -p/--password, -P/--passwords-file, -H/--hashes-file, or --hash is required")


def _validate_kerberos(ns: argparse.Namespace, p: argparse.ArgumentParser) -> None:
    has_user_key_file = getattr(ns, "user_key_file", None)
    has_user = getattr(ns, "user", None) or getattr(ns, "users_file", None)
    has_password = getattr(ns, "password", None) is not None
    has_passwords_file = bool(getattr(ns, "passwords_file", None))
    has_key_list = bool(
        getattr(ns, "rc4_file", None) or getattr(ns, "aes128_file", None) or getattr(ns, "aes256_file", None),
    )
    has_inline_key = bool(
        getattr(ns, "rc4_key", None) or getattr(ns, "aes128_key", None) or getattr(ns, "aes256_key", None),
    )
    has_ticket = bool(getattr(ns, "ticket", None))

    if has_user_key_file:
        # user:key file is self-contained — reject all other sources.
        if has_user:
            p.error("--user-key-file cannot be combined with -u/--user or -U/--users-file")
        if has_password or has_passwords_file or has_key_list or has_inline_key or has_ticket:
            p.error(
                "--user-key-file cannot be combined with -p/--password, -P/--passwords-file, --rc4-key, --aes128-key, --aes256-key, --rc4-file, --aes128-file, --aes256-file, or --ticket",
            )
        return

    if not has_user:
        p.error("one of -u/--user or -U/--users-file is required")

    # Count how many mutually exclusive secret categories are active.
    password_cat = has_password or has_passwords_file
    categories = sum([password_cat, has_key_list, has_inline_key, has_ticket])

    if categories == 0:
        p.error("at least one secret source is required (-p/--password, -P/--passwords-file, --rc4-key, --rc4-file, --ticket, etc.)")
    if categories > 1:
        p.error(
            "passwords (-p/--password, -P/--passwords-file), inline keys (--rc4-key/--aes128-key/--aes256-key), key lists (--rc4-file/--aes128-file/--aes256-file), and --ticket are mutually exclusive",
        )

    # Within passwords, -p/--password and -P/--passwords-file are not in an argparse
    # mutual exclusion group because they share the group with key lists. Enforce here.
    if has_password and has_passwords_file:
        p.error("-p/--password and -P/--passwords-file are mutually exclusive")


def _validate_userenum(ns: argparse.Namespace, p: argparse.ArgumentParser) -> None:
    has_user = getattr(ns, "user", None) or getattr(ns, "users_file", None)
    if not has_user:
        p.error("one of -u/--user or -U/--users-file is required")


def _namespace_to_options(ns: argparse.Namespace) -> AttackOptions:
    """Convert an argparse Namespace to the typed :class:`AttackOptions` dataclass."""
    opts = AttackOptions(protocol=Protocol(ns.protocol))

    for field_name in vars(opts):
        if field_name == "protocol":
            continue
        if hasattr(ns, field_name):
            val = getattr(ns, field_name)
            if val is not None:
                object.__setattr__(opts, field_name, val)

    # Map string enum values back to enum types.
    if hasattr(ns, "ntlm_transport") and ns.ntlm_transport is not None:
        opts.ntlm_transport = NtlmTransport(ns.ntlm_transport)
    if hasattr(ns, "kdc_transport") and ns.kdc_transport is not None:
        opts.kdc_transport = TransportProtocol(ns.kdc_transport)
    if hasattr(ns, "etype") and ns.etype is not None:
        opts.etype = EncryptionType(ns.etype)

    # Propagate global flags.
    opts.verbosity = ns.verbosity
    opts.stop_on_success = ns.stop_on_success
    opts.delay = ns.delay
    opts.jitter = ns.jitter
    opts.timeout = ns.timeout
    opts.max_lockouts = ns.max_lockouts

    return opts


def _describe_user(options: AttackOptions) -> str:
    """Describe the user source for the header."""
    if options.user_pass_file or options.user_hash_file or options.user_key_file:
        return "paired"
    if options.user:
        return f"{options.user} (inline)"
    if options.users_file:
        return f"file ({options.users_file})"
    return "-"


def _describe_secret(options: AttackOptions) -> str:
    """Describe the secret source for the header."""
    if options.user_pass_file:
        return f"user:password ({options.user_pass_file})"
    if options.user_hash_file:
        return f"user:nt_hash ({options.user_hash_file})"
    if options.user_key_file:
        return f"user:key ({options.user_key_file})"
    if options.password is not None:
        return "password (inline)"
    if options.passwords_file:
        return f"password ({options.passwords_file})"
    if options.hashes_file:
        return f"nt_hash ({options.hashes_file})"
    if options.hash_value:
        return "nt_hash (inline)"
    inline_parts: list[str] = []
    if options.rc4_key:
        inline_parts.append("rc4_key")
    if options.aes128_key:
        inline_parts.append("aes128_key")
    if options.aes256_key:
        inline_parts.append("aes256_key")
    if inline_parts:
        return f"{', '.join(inline_parts)} (inline)"
    file_parts: list[str] = []
    if options.rc4_file:
        file_parts.append(f"rc4_key ({options.rc4_file})")
    if options.aes128_file:
        file_parts.append(f"aes128_key ({options.aes128_file})")
    if options.aes256_file:
        file_parts.append(f"aes256_key ({options.aes256_file})")
    if file_parts:
        return ", ".join(file_parts)
    if options.ticket:
        return f"ticket ({options.ticket})"
    return "-"


def _print_header(options: AttackOptions) -> None:
    """Print a summary header of the attack configuration."""
    parts = [f"credwolf v{__version__}", ""]
    parts.append(f"  Protocol  : {options.protocol}")
    if options.protocol == Protocol.NTLM:
        parts.append(f"  Transport : {options.ntlm_transport}")
    elif options.protocol == Protocol.USERENUM:
        parts.append(f"  Transport : {options.kdc_transport}")
    else:
        parts.append(f"  Transport : {options.kdc_transport}")
        parts.append(f"  Etype     : {options.etype}")
    target = options.dc_ip if options.protocol == Protocol.NTLM else options.kdc_ip
    parts.append(f"  Domain    : {options.domain}")
    parts.append(f"  Target    : {target or options.domain}")
    parts.append(f"  User      : {_describe_user(options)}")
    if options.protocol != Protocol.USERENUM:
        parts.append(f"  Secret    : {_describe_secret(options)}")
    if options.delay > 0 or options.jitter > 0:
        delay_str = f"{options.delay}s"
        if options.jitter > 0:
            delay_str += f" (+/- {options.jitter}s jitter)"
        parts.append(f"  Delay     : {delay_str}")
    _default_timeout = 15.0
    if options.timeout != _default_timeout:
        timeout_str = "none (infinite)" if options.timeout == 0 else f"{options.timeout}s"
        parts.append(f"  Timeout   : {timeout_str}")
    if options.stop_on_success:
        parts.append("  Stop      : on first success")
    if options.max_lockouts > 0:
        parts.append(f"  Lockouts  : stop after {options.max_lockouts} consecutive")
    if options.output_file:
        parts.append(f"  Output    : {options.output_file}")
    parts.append("")
    print("\n".join(parts))


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint."""
    parser, ntlm_parser, kerberos_parser, userenum_parser = _build_parser()
    ns = parser.parse_args(argv)
    _validate(ns, parser, ntlm_parser, kerberos_parser, userenum_parser)

    options = _namespace_to_options(ns)
    logger = Logger(options.verbosity)

    _print_header(options)
    logger.info("Starting credential validation")

    try:
        with contextlib.ExitStack() as stack:
            output_fh = None
            if options.output_file:
                try:
                    output_fh = stack.enter_context(Path(options.output_file).open("w"))
                except OSError as exc:
                    logger.error(f"Cannot open output file: {exc}")
                    return
            runner = AttackRunner(options, logger, output_fh)
            runner.run()
    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
