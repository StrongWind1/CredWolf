# credwolf

[![CI](https://github.com/StrongWind1/CredWolf/actions/workflows/ci.yml/badge.svg)](https://github.com/StrongWind1/CredWolf/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Credential validation tool for Active Directory Domain Services.

credwolf tests username and secret combinations (passwords, NT hashes, Kerberos keys, or ticket files) against a domain controller and reports which credentials are valid. It also supports username enumeration via Kerberos to discover valid AD accounts without causing login attempts. It is designed for authorized penetration testing, red team engagements, and security audits where you need to verify whether recovered or suspected credentials are active.

## How it differs from other tools

Most credential testing tools (CrackMapExec/NetExec, Sprayhound, Kerbrute) are built around exploitation workflows — they authenticate and then enumerate shares, dump SAM, exec commands, etc. credwolf does one thing: **validate credentials**. It does not attempt any post-authentication activity.

- **Protocol coverage** — NTLM (SMB, LDAP, LDAPS) and Kerberos pre-authentication in a single tool, with every meaningful combination of user sources and secret sources.
- **Clean output** — valid credentials are printed in a machine-parseable `domain/user:secret@type` format. No tables, no colors in the output line, easy to `grep` or pipe.
- **Safety-first error handling** — clock skew stops execution immediately (instead of silently producing false negatives), `KRB_ERR_RESPONSE_TOO_BIG` tells you to switch to TCP (instead of guessing validity), and raw SMB error codes are passed through (instead of hiding them behind generic messages).
- **Username enumeration** — discover valid AD accounts via Kerberos without triggering login failures or account lockouts. ASREProastable accounts (pre-authentication not required) are flagged automatically.
- **Rate limiting** — built-in `--delay` and `--jitter` to avoid triggering account lockout policies.

## Supported protocols

| Protocol | Transport | Secret types |
|----------|-----------|--------------|
| **NTLM** | SMB (default), LDAP, LDAPS | Password, NT hash |
| **Kerberos** | UDP (default), TCP | Password, RC4 key, AES128 key, AES256 key, ticket (ccache/kirbi) |

## Installation

Requires Python 3.11+. Install with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/StrongWind1/CredWolf
```

## Quick start

```bash
# Validate an NT hash over SMB (pass-the-hash)
$ credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f
[+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# Validate an AES256 key over Kerberos (pass-the-key)
$ credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
[+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key

# Validate an NT hash as RC4 key over Kerberos (overpass-the-hash)
$ credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --transport tcp
[+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key
```

## CLI reference

### Global options

| Short | Long | Description |
|-------|------|-------------|
| `-d` | `--domain` | Domain name (required) |
| `-o` | `--output` | Write valid credentials to file |
| `-v` | `--verbose` | Verbosity level (`-v` verbose, `-vv` debug, `-vvv` trace) |
| | `--stop-on-success` | Stop on first valid credential |
| | `--delay` | Seconds to wait between attempts (default: 0) |
| | `--jitter` | Random jitter +/- seconds added to delay (default: 0) |
| | `--timeout` | Connection timeout in seconds; 0 for no timeout (default: 15) |
| | `--max-lockouts` | Stop after N consecutive revoked accounts; 0 to disable (default: 0) |
| | `--version` | Show version and exit |

### NTLM options

| Short | Long | Description |
|-------|------|-------------|
| `-u` | `--user` | Single username |
| `-U` | `--users-file` | File containing usernames (one per line) |
| `-p` | `--password` | Single password |
| `-P` | `--passwords-file` | File containing passwords (one per line) |
| `-H` | `--hashes-file` | File containing NT hashes or LM:NT pairs (one per line) |
| | `--hash` | Single hash (NT or LM:NT format) |
| | `--user-pass-file` | Colon-separated `user:password` file |
| | `--user-hash-file` | Colon-separated `user:hash` file (NT or LM:NT) |
| | `--dc-ip` | Domain controller IP (required) |
| | `--transport` | Transport protocol: `smb` (default), `ldap`, `ldaps` |

### Kerberos options

| Short | Long | Description |
|-------|------|-------------|
| `-u` | `--user` | Single username |
| `-U` | `--users-file` | File containing usernames (one per line) |
| `-p` | `--password` | Single password |
| `-P` | `--passwords-file` | File containing passwords (one per line) |
| | `--rc4-key` | Single RC4/NT key (32 hex chars) |
| | `--aes128-key` | Single AES128 key (32 hex chars) |
| | `--aes256-key` | Single AES256 key (64 hex chars) |
| | `--rc4-file` | File containing RC4/NT keys (one per line) |
| | `--aes128-file` | File containing AES128 keys (one per line) |
| | `--aes256-file` | File containing AES256 keys (one per line) |
| | `--ticket` | Ticket file containing a TGT (`.ccache` or `.kirbi`, auto-detected) |
| | `--user-key-file` | Colon-separated `user:key` file (auto-detects key type) |
| | `--kdc-ip` | KDC IP address (required) |
| | `--transport` | Transport protocol: `udp` (default), `tcp` |
| `-e` | `--etype` | Encryption type: `rc4` (default), `aes128`, `aes256` |

### Username enumeration options

| Short | Long | Description |
|-------|------|-------------|
| `-u` | `--user` | Single username |
| `-U` | `--users-file` | File containing usernames (one per line) |
| | `--kdc-ip` | KDC IP address (required) |
| | `--transport` | Transport protocol: `udp` (default), `tcp` |

## Output format

Valid credentials are printed as:

```
domain/user:secret@type
```

Where `type` is one of: `password`, `nt_hash`, `rc4_key`, `aes128_key`, `aes256_key`, `ccache`, `kirbi`.

Examples:

```
evil.corp/Administrator:Password1!@password
evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash
evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key
evil.corp/Administrator:4bbb66ffd90a18f248b909016eb4b75f@aes128_key
evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key
```

When writing to a file with `-o`/`--output`, the same format is used (one line per valid credential, no color or status prefixes).

## Usage examples

### NTLM

Test credentials over SMB (default), LDAP, or LDAPS.

```bash
# Single user + single password
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'

# Single user + single inline hash (NT format)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# Single user + single inline hash (LM:NT format, from secretsdump)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f'
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# User list + password list
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt

# Single user + hash file (NT hashes or LM:NT pairs, one per line)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -H hashes.txt

# User list + hash file
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -H hashes.txt

# Pre-paired user:password file (one user:password per line)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 --user-pass-file creds.txt

# Pre-paired user:hash file (one user:hash per line, NT or LM:NT format)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 --user-hash-file creds.txt

# Use LDAP transport instead of SMB
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f --transport ldap
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# Use LDAPS transport
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f --transport ldaps
```

### Kerberos

Test credentials via Kerberos pre-authentication.

```bash
# Single user + single password (RC4 encryption, UDP transport)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator -p 'Password1!'

# Password with AES256 or AES128 encryption
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator -p 'Password1!' -e aes256
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator -p 'Password1!' -e aes128

# User list + password list
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt

# Overpass-the-hash: use NT hash as RC4 key
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --transport tcp
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key

# Pass-the-key with AES256 (from secretsdump/dcsync aes256-cts-hmac-sha1-96 field)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
# [+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key

# Pass-the-key with AES128 (from secretsdump/dcsync aes128-cts-hmac-sha1-96 field)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes128-key 4bbb66ffd90a18f248b909016eb4b75f --transport tcp
# [+] evil.corp/Administrator:4bbb66ffd90a18f248b909016eb4b75f@aes128_key

# Combine multiple inline keys (all tested per user)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key
# [+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key

# User list + key file
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --rc4-file rc4_keys.txt --transport tcp
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --aes128-file aes128_keys.txt --transport tcp
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --aes256-file aes256_keys.txt --transport tcp

# Multiple key files combined (keys pooled, tested per user)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --rc4-file rc4.txt --aes128-file aes128.txt --aes256-file aes256.txt --transport tcp

# Pre-paired user:key file (auto-detects RC4 vs AES256 by key length)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt --transport tcp

# user:key file with AES128 disambiguation (treats 32-hex keys as AES128)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt -e aes128 --transport tcp

# Validate a ticket (auto-detects ccache vs kirbi format)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --ticket admin.ccache
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --ticket admin.kirbi
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --ticket krb5.ccache

# Use TCP transport (required when KDC returns KRB_ERR_RESPONSE_TOO_BIG)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```

### Username enumeration

Discover valid AD usernames via Kerberos. This sends bare AS-REQs without pre-authentication — it does not cause login attempts and does not increment the bad-password counter.

```bash
# Enumerate a single user
credwolf -d evil.corp userenum --kdc-ip 10.0.0.1 -u Administrator

# Enumerate from a user list
credwolf -d evil.corp userenum --kdc-ip 10.0.0.1 -U users.txt

# Use TCP transport
credwolf -d evil.corp userenum --kdc-ip 10.0.0.1 -U users.txt --transport tcp

# Write valid usernames to a file
credwolf -d evil.corp -o valid_users.txt userenum --kdc-ip 10.0.0.1 -U users.txt
```

Output:
```
[+] evil.corp/Administrator
[+] evil.corp/lmuser
[+] evil.corp/Guest — KDC_ERR_CLIENT_REVOKED
[+] evil.corp/krbtgt — KDC_ERR_CLIENT_REVOKED
[*] Enumeration complete: 4/6 users found
```

ASREProastable accounts (pre-authentication not required) are flagged:
```
[+] evil.corp/svc_backup — no_preauth (ASREProastable)
```

### Global options

```bash
# Write valid credentials to a file
credwolf -d evil.corp -o results.txt ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt

# Verbose output (-v), debug output (-vv), or trace (-vvv)
credwolf -v -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'
credwolf -vv -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --transport tcp

# Stop on first valid credential
credwolf --stop-on-success -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -H hashes.txt

# Add delay between attempts (seconds) with optional jitter
credwolf --delay 1.5 -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt
credwolf --delay 2 --jitter 0.5 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp

# Custom connection timeout (default: 15s; 0 = no timeout / infinite wait)
credwolf --timeout 60 -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt
credwolf --timeout 0 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp

# Stop after N consecutive revoked accounts (disabled/expired/locked out)
credwolf --max-lockouts 3 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```

## Hash and key formats

### NTLM hashes (`--hash`, `-H`/`--hashes-file`, `--user-hash-file`)

Each value is either a bare NT hash or an LM:NT pair. LM hashes are accepted as input but never shown in output — only the NT hash is displayed.

```
7facdc498ed1680c4fd1448319a8c04f
aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
```

Both formats can be mixed in the same file. Invalid lines are skipped with a warning.

### Kerberos keys

| Type | Bytes | Hex chars | Inline flag | File flag |
|------|-------|-----------|-------------|-----------|
| RC4 | 16 | 32 | `--rc4-key` | `--rc4-file` |
| AES128 | 16 | 32 | `--aes128-key` | `--aes128-file` |
| AES256 | 32 | 64 | `--aes256-key` | `--aes256-file` |

**RC4/AES128 ambiguity:** RC4 and AES128 keys are both 32 hex characters and cannot be distinguished by length. The `--user-key-file` auto-detection defaults 32-char keys to RC4. To treat them as AES128 instead, pass `-e aes128`:

```bash
# 32-hex keys treated as RC4 (default)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt --transport tcp

# 32-hex keys treated as AES128
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt -e aes128 --transport tcp
```

64-hex keys are always AES256 regardless of `--etype`.

## Working with secretsdump output

credwolf accepts hashes and keys directly from Impacket's `secretsdump.py` / DCSync output. Here's how each format maps to credwolf flags:

**SAM / NTDS dump** (`user:RID:LM:NT:::`):

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
```

Use the NT hash (4th field) with `--hash` for NTLM or `--rc4-key` for Kerberos:

```bash
# NTLM pass-the-hash
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# The LM:NT pair is also accepted
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f'
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# Kerberos overpass-the-hash (NT hash = RC4 key)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --transport tcp
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key
```

**Kerberos keys** (`user:etype:key`):

```
Administrator:aes256-cts-hmac-sha1-96:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925
Administrator:aes128-cts-hmac-sha1-96:4bbb66ffd90a18f248b909016eb4b75f
```

Use the hex key (3rd field) with the matching `--aes256-key` or `--aes128-key` flag:

```bash
# AES256 pass-the-key
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
# [+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key

# AES128 pass-the-key
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes128-key 4bbb66ffd90a18f248b909016eb4b75f --transport tcp
# [+] evil.corp/Administrator:4bbb66ffd90a18f248b909016eb4b75f@aes128_key

# All three key types combined in one run
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key
# [+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key
```

## Error handling

credwolf handles protocol errors explicitly rather than hiding them. Error descriptions are specific to Windows Active Directory.

### NTLM errors

| Error | Behavior |
|-------|----------|
| `STATUS_LOGON_FAILURE` | Silent — credential is invalid |
| Other SMB status codes | Displayed as a warning with the raw status code |
| Connection failure | **Stops execution** — no point retrying if the DC is unreachable |

### Kerberos errors

All Kerberos errors are displayed as `RAW_CODE (human explanation)` with the affected username.

| Error | Code | Behavior |
|-------|------|----------|
| `KDC_ERR_PREAUTH_FAILED` | 0x18 | Silent — wrong password or key |
| `KDC_ERR_KEY_EXPIRED` | 0x17 | **Reported as valid** — the password is correct but expired (`pwdLastSet=0`). Maps to NTLM `STATUS_PASSWORD_MUST_CHANGE`. This confirms the credential. |
| `KDC_ERR_CLIENT_REVOKED` | 0x12 | Warning — account is disabled, expired, locked out, or outside logon hours. Kerberos uses this single error code for all four; only NTLM distinguishes them (see table below). Skips subsequent attempts for that user. |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 0x6 | User does not exist in AD. Skips subsequent attempts for that user. |
| `KDC_ERR_POLICY` | 0xC | Warning (indeterminate) — logon restricted by AD policy, typically smart card required (`SmartcardLogonRequired` flag). The password may or may not be correct — AD blocks the attempt before checking the credential. |
| `KDC_ERR_NAME_EXP` | 0x1 | Account entry expired in AD. Skips subsequent attempts for that user. |
| `KDC_ERR_CLIENT_NOTYET` | 0x15 | Account not yet valid (future start date in AD). Skips subsequent attempts for that user. |
| `KDC_ERR_NULL_KEY` | 0x9 | No key set on account — password may need to be reset by an admin. Skips subsequent attempts for that user. |
| `KDC_ERR_ETYPE_NOSUPP` | 0xE | The account's `msDS-SupportedEncryptionTypes` or `USE_DES_KEY_ONLY` flag rejects the requested etype. Try a different `--etype`. These accounts exist and may have valid passwords — they just can't authenticate via the requested cipher. |
| `KRB_ERR_RESPONSE_TOO_BIG` | 0x34 | AS-REP exceeds UDP datagram size. Retry with `--transport tcp`. |
| `KRB_AP_ERR_SKEW` | 0x25 | **Stops execution** — clock out of sync with KDC. All Kerberos results are unreliable until clocks are synced. Reports the server time if available. |
| `KDC_ERR_WRONG_REALM` | 0x44 | Incorrect domain or principal (typically misconfigured DNS). Skips subsequent attempts for that user. |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | 0x3E | Smart card certificate revoked or untrusted CA. |
| `KRB_ERR_GENERIC` | 0x3C | Generic KDC error — PAC too large, SPN issues, crypto subsystem errors. |
| Connection failure | | **Stops execution** — no point retrying if the KDC is unreachable |

### What Kerberos hides — NTLM vs Kerberos error mapping

Kerberos collapses several distinct account states into a single error code. If you need to know the specific reason an account is blocked, test it over NTLM (`credwolf ntlm`).

| NTLM status (specific) | Kerberos error (generic) | AD attribute / cause |
|---|---|---|
| `STATUS_ACCOUNT_DISABLED` | `KDC_ERR_CLIENT_REVOKED` | `userAccountControl` ACCOUNTDISABLE bit or `Enabled=$false` |
| `STATUS_ACCOUNT_EXPIRED` | `KDC_ERR_CLIENT_REVOKED` | `accountExpires` date in the past |
| `STATUS_INVALID_LOGON_HOURS` | `KDC_ERR_CLIENT_REVOKED` | `logonHours` attribute blocks the current time |
| `STATUS_ACCOUNT_RESTRICTION` | Kerberos succeeds | Protected Users group — NTLM blocked, Kerberos AES works |
| `STATUS_PASSWORD_MUST_CHANGE` | `KDC_ERR_KEY_EXPIRED` | `pwdLastSet=0` (must change at next logon) |

### Username enumeration error behavior

During `userenum`, only `KDC_ERR_C_PRINCIPAL_UNKNOWN` means the user does not exist. Every other KDC error — including `KDC_ERR_CLIENT_REVOKED`, `KDC_ERR_ETYPE_NOSUPP`, and `KDC_ERR_POLICY` — confirms the user exists because the KDC looked up the principal before returning the error. ASREProastable accounts (pre-authentication not required) return an `AS-REP` instead of an error.

## Kerberos authentication flow and account lockout

### Requests per credential type

| Credential type | KDC requests | Counts as login attempt? |
|----------------|-------------|--------------------------|
| Password (RC4 etype) | 1 AS-REQ with encrypted timestamp | Yes — 1 attempt |
| Password (AES128/AES256 etype) | 1 bare AS-REQ (salt retrieval) + 1 AS-REQ with encrypted timestamp | Only the 2nd counts — 1 attempt |
| Raw key (RC4/AES128/AES256) | 1 AS-REQ with encrypted timestamp | Yes — 1 attempt |
| Ticket file (ccache/kirbi) | 1 TGS-REQ | No — not a password attempt |
| Username enumeration | 1 bare AS-REQ (no pre-auth data) | No — not a login attempt |

### How it works

Kerberos pre-authentication proves knowledge of a user's key by encrypting the current timestamp with it. The KDC decrypts the timestamp — if it succeeds, the credential is valid (AS-REP returned). If it fails, `KDC_ERR_PREAUTH_FAILED` is returned and the bad-password counter increments by one.

**AES salt retrieval is harmless.** AES key derivation requires a per-user salt from the KDC. credwolf obtains this by sending an AS-REQ with no authentication data. The KDC responds with `KDC_ERR_PREAUTH_REQUIRED` and the salt — this is standard protocol behavior, not a login attempt. The salt is cached per user, so this only happens once regardless of how many passwords are tested against the same user.

**Each wrong password/key = exactly 1 failed login.** The mapping is 1:1 — no hidden extra requests that inflate the bad-password counter. This is the same as typing a wrong password interactively.

**Ticket validation does not touch the password counter.** The `--ticket` flag sends a TGS-REQ (not an AS-REQ), which validates the TGT without any password involvement.

### Comparison with kerbrute

Kerbrute sends bare AS-REQs for user enumeration. On certain Active Directory configurations, these requests were counted as failed login attempts, causing unintended lockouts during large-scale enumeration. credwolf uses the same bare AS-REQ for both `userenum` and AES salt retrieval, but:

- **User enumeration** (`userenum`) sends one bare AS-REQ per user with all three encryption types (AES256, AES128, RC4). This is not a login attempt and does not increment the bad-password counter.
- **AES salt retrieval** (during `kerberos` password auth with `-e aes128` or `-e aes256`) sends the bare AS-REQ at most once per user. The salt is cached.
- **RC4 password auth and raw keys** do not send any bare AS-REQ — they go directly to pre-authentication.

Additionally, credwolf's `userenum` detects `KDC_ERR_ETYPE_NOSUPP` as a valid-user signal (the KDC looked up the principal before rejecting the encryption type), which tools that only check for `PREAUTH_REQUIRED` would miss.

### Lockout mitigation

Use `--delay` and `--jitter` to space out attempts when testing against accounts with lockout policies:

```bash
# 2-second delay with 0.5s random jitter between each attempt
credwolf --delay 2 --jitter 0.5 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp

# Stop after the first valid credential (minimizes total attempts)
credwolf --stop-on-success -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp

# Stop after 3 consecutive revoked accounts (likely means the scan is causing lockouts)
credwolf --max-lockouts 3 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```

**Note on `KDC_ERR_CLIENT_REVOKED`:** This Kerberos error code does not distinguish between accounts that are disabled, expired, locked out, or outside their allowed logon hours. credwolf reports all four possibilities in the warning message. The `--max-lockouts` flag counts consecutive `CLIENT_REVOKED` responses — if your scan triggers N in a row, it is likely that the scan itself is causing lockouts rather than encountering pre-existing disabled/expired accounts. To determine the specific cause, test the affected accounts over NTLM (`credwolf ntlm`).

## Credential combination matrix

### NTLM (x3 transports: SMB, LDAP, LDAPS)

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 1 | `-u`/`--user` | `-p`/`--password` | 1 attempt |
| 2 | `-u`/`--user` | `-P`/`--passwords-file` | iterate passwords |
| 3 | `-u`/`--user` | `--hash` | 1 attempt |
| 4 | `-u`/`--user` | `-H`/`--hashes-file` | iterate hashes |
| 5 | `-U`/`--users-file` | `-p`/`--password` | password spray |
| 6 | `-U`/`--users-file` | `-P`/`--passwords-file` | cartesian product |
| 7 | `-U`/`--users-file` | `--hash` | hash spray |
| 8 | `-U`/`--users-file` | `-H`/`--hashes-file` | cartesian product |
| 9 | `--user-pass-file` | (user:password embedded) | paired lines |
| 10 | `--user-hash-file` | (user:hash embedded) | paired lines |

All 10 combinations work over each of the 3 transports (**30 total permutations**).

### Kerberos (x2 transports: UDP, TCP)

**Password-based** (x3 etypes: RC4, AES128, AES256):

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 1 | `-u`/`--user` | `-p`/`--password` | 1 attempt |
| 2 | `-u`/`--user` | `-P`/`--passwords-file` | iterate passwords |
| 3 | `-U`/`--users-file` | `-p`/`--password` | password spray |
| 4 | `-U`/`--users-file` | `-P`/`--passwords-file` | cartesian product |

4 combinations x 3 etypes x 2 transports = **24 permutations**.

**Inline key-based:**

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 5 | `-u`/`--user` | `--rc4-key` | 1 attempt |
| 6 | `-u`/`--user` | `--aes128-key` | 1 attempt |
| 7 | `-u`/`--user` | `--aes256-key` | 1 attempt |
| 8 | `-U`/`--users-file` | `--rc4-key` | key spray |
| 9 | `-U`/`--users-file` | `--aes128-key` | key spray |
| 10 | `-U`/`--users-file` | `--aes256-key` | key spray |

Inline keys of different types can be combined (e.g., `--rc4-key X --aes256-key Y`). 6+ combinations x 2 transports = **12+ permutations**.

**Key file-based** (files can be combined):

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 11 | `-u`/`-U` | `--rc4-file` | cartesian product |
| 12 | `-u`/`-U` | `--aes128-file` | cartesian product |
| 13 | `-u`/`-U` | `--aes256-file` | cartesian product |
| 14 | `-u`/`-U` | multiple key files combined | pooled cartesian product |

Key files pool into a single list and iterate per user. 8+ combinations x 2 transports = **16+ permutations**.

**Ticket and paired files:**

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 15 | `-u`/`--user` | `--ticket` | validate TGT |
| 16 | `-U`/`--users-file` | `--ticket` | validate TGT per user |
| 17 | `--user-key-file` | (user:key embedded, auto-detect) | paired lines |

3 combinations x 2 transports = **6 permutations**.

**Kerberos total: 58+ permutations.** Combined with NTLM: **88+ total permutations.**

### Mutual exclusion rules

**NTLM secret sources** are mutually exclusive (enforced by argparse): `-p`/`--password`, `-P`/`--passwords-file`, `-H`/`--hashes-file`, `--hash`, `--user-pass-file`, `--user-hash-file`.

**Kerberos secret categories** are mutually exclusive (enforced by validation):
- Passwords: `-p`/`--password`, `-P`/`--passwords-file`
- Inline keys: `--rc4-key`, `--aes128-key`, `--aes256-key` (combinable with each other)
- Key files: `--rc4-file`, `--aes128-file`, `--aes256-file` (combinable with each other)
- Ticket: `--ticket` (ccache or kirbi)
- Paired file: `--user-key-file` (standalone — no `-u`/`-U` allowed)

## Development

```bash
uv sync                        # install dev dependencies
uv run pytest                  # run tests
uv run ruff check              # lint
uv run ruff format --check     # format check
uv run ty check                # type check
uv build                       # build
```

## Known limitations

- Credential testing runs sequentially. Thread-based parallelism is not yet implemented.
- Kerberos over UDP may produce `KRB_ERR_RESPONSE_TOO_BIG` for some users. Use `--transport tcp` as a workaround.
- Clock skew between the client and KDC causes `KRB_AP_ERR_SKEW`. Sync your system clock before running Kerberos authentication.
- AES128 and RC4 Kerberos keys share the same hex length (32 chars). Auto-detection in `--user-key-file` defaults to RC4; use `-e aes128` to override.
- Protected Users group members and accounts with `USE_DES_KEY_ONLY` or restricted `msDS-SupportedEncryptionTypes` will fail with `KDC_ERR_ETYPE_NOSUPP` when using the default `--etype rc4`. Use `--etype aes256` for these accounts. The `userenum` subcommand is unaffected because it requests all encryption types.
- LDAPS transport requires the domain controller to have a valid TLS certificate configuration. Connection resets typically indicate LDAPS is not available on the target.
- LM hashes are accepted as input (for compatibility with hash dumps) but are not used for authentication or shown in output. Only the NT hash portion is used.

## Roadmap

- **AS-REP hash extraction** — when `userenum` discovers an ASREProastable account (pre-authentication not required), the KDC returns an AS-REP containing encrypted data that can be cracked offline with hashcat (`$krb5asrep$23$`). credwolf currently flags these accounts but discards the AS-REP. A `--asrep-out` flag would save the hashes in hashcat format.
- **Parallel execution** — credential testing is currently sequential. Thread-based or async parallelism would significantly improve speed for large user/password lists, especially over TCP where connection setup dominates.
- **Automatic etype fallback** — when `KDC_ERR_ETYPE_NOSUPP` is returned during credential validation, automatically retry the user with AES256 instead of requiring the operator to re-run with `--etype aes256`. This would catch Protected Users members and DES-only accounts in a single pass.
- **`--realm` override** — allow the Kerberos realm to be set independently of the domain name (currently force-uppercased from `-d`). Would enable testing against non-standard realm configurations.

## Credits

Built on [Impacket](https://github.com/fortra/impacket). Inspired by [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), [Kerbrute](https://github.com/ropnop/kerbrute), [smartbrute](https://github.com/ShutdownRepo/smartbrute), and [SprayHound](https://github.com/Hackndo/sprayhound).

## License

[Apache License 2.0](LICENSE)
