# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2025-06-01

### Added

- NTLM credential validation over SMB, LDAP, and LDAPS
- Kerberos pre-authentication over UDP and TCP
- Support for passwords, NT hashes, RC4 keys, AES128 keys, AES256 keys, and ticket files (ccache/kirbi)
- Username enumeration via Kerberos (no login attempt, no bad-password counter increment)
- ASREProastable account detection during enumeration
- User:password, user:hash, and user:key paired file support
- Auto-detection of ccache vs kirbi ticket format
- Auto-detection of key type by hex length in `--user-key-file`
- AES salt caching (one KDC round-trip per user regardless of password count)
- Clock skew detection with immediate stop and server time reporting
- Per-user skip on `KDC_ERR_C_PRINCIPAL_UNKNOWN`, `CLIENT_REVOKED`, `WRONG_REALM`
- Account status detection: disabled, expired, locked, revoked, not-yet-valid, null-key
- `--delay` and `--jitter` for rate limiting
- `--max-lockouts` for consecutive revoked account safety
- `--stop-on-success` to halt on first valid credential
- Machine-parseable output format: `domain/user:secret@type`
- File output with `-o`/`--output`
- Three verbosity levels (`-v`, `-vv`, `-vvv`)
- CLI alias `cw` for `credwolf`

[1.0.0]: https://github.com/StrongWind1/CredWolf/releases/tag/v1.0.0
