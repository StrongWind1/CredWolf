# How it differs from other tools

Most credential testing tools are built around exploitation workflows — they authenticate and then enumerate shares, dump SAM, exec commands, etc. CredWolf does one thing: **validate credentials**. It does not attempt any post-authentication activity.

## Key strengths

- **Protocol coverage** — NTLM (SMB, LDAP, LDAPS) and Kerberos pre-authentication in a single tool, with every meaningful combination of user sources and secret sources (88+ permutations).
- **Clean output** — valid credentials are printed in a machine-parseable `domain/user:secret@type` format. No tables, no colors in the output line, easy to `grep` or pipe.
- **Safety-first error handling** — clock skew stops execution immediately (instead of silently producing false negatives), `KRB_ERR_RESPONSE_TOO_BIG` tells you to switch to TCP (instead of guessing validity), and raw SMB error codes are passed through (instead of hiding them behind generic messages).
- **Username enumeration** — discover valid AD accounts via Kerberos without triggering login failures or account lockouts. ASREProastable accounts (pre-authentication not required) are flagged automatically.
- **Rate limiting** — built-in `--delay`, `--jitter`, and `--max-lockouts` to avoid triggering account lockout policies.

## Comparison table

| Feature | **CredWolf** | [kerbrute](https://github.com/ropnop/kerbrute) | [ADSpray](https://github.com/ZephrFish/ADSpray) | [NetExec](https://github.com/Pennyw0rth/NetExec) | [smartbrute](https://github.com/ShutdownRepo/smartbrute) | [pyKerbrute](https://github.com/3gstudent/pyKerbrute) | [SprayHound](https://github.com/Hackndo/sprayhound) | [SmartSpray](https://github.com/GabrielDuschl/SmartSpray) |
|---|---|---|---|---|---|---|---|---|
| **Focus** | Credential validation only | Kerberos spray/enum | Credential spraying | Post-exploitation framework | Smart brute-force | Kerberos spray/enum | Password spraying | Password spraying |
| **Language** | Python 3.11+ | Go | Python 3 | Python 3 | Python 3.6+ | Python 2 | Python 3.6+ | Python 3.6+ |
| **NTLM auth** | SMB, LDAP, LDAPS | — | LDAP, LDAPS | SMB, LDAP, LDAPS, WinRM, MSSQL, RDP, SSH, FTP, VNC, NFS, WMI | SMB, LDAP, LDAPS | — | LDAP, LDAPS | SMB |
| **Kerberos pre-auth** | UDP, TCP | UDP (auto) | via Impacket | via Impacket | UDP, TCP | UDP, TCP | — | — |
| **Passwords** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **NT hashes** | Yes (bare + LM:NT) | — | Yes | Yes | Yes | Yes | — | — |
| **AES128 / AES256 keys** | Yes (inline + file) | — | — | AES keys supported | AES128, AES256 | — | — | — |
| **RC4 keys** | Yes (inline + file) | — | — | — | Yes | — | — | — |
| **Ticket files (ccache/kirbi)** | Yes (auto-detect) | — | — | ccache | ccache | — | — | — |
| **User:secret paired files** | user:pass, user:hash, user:key | user:pass (bruteforce mode) | — | — | — | — | — | — |
| **Username enumeration** | Yes (Kerberos, no login attempt) | Yes (Kerberos, no login attempt) | LDAP + Kerberos | RID brute, LDAP | LDAP (smart mode) | Yes (Kerberos) | — | — |
| **ASREProastable detection** | Yes (flagged during enum) | Yes (AS-REP hash capture) | — | Yes (dedicated flag) | — | — | — | — |
| **Clock skew handling** | Stops execution with server time | Logs warning, continues | — | — | Logs warning | — | — | — |
| **Account status detection** | Disabled, expired, locked, revoked, not-yet-valid, null-key | Locked, expired | Disabled, locked, expired | Disabled, expired, locked, must-change, restriction | Disabled, expired, must-change | — | Disabled (LDAP filter) | — |
| **Per-user skip on error** | Yes (unknown, revoked, wrong realm) | — | — | — | — | — | — | — |
| **Delay / jitter** | Yes / Yes | Delay only (forces single-thread) | Yes / Yes | Jitter only | Delay only | — | — | Stealth mode (0.5–1.5s) |
| **Max lockout safety** | `--max-lockouts` (consecutive revoked) | `--safe` (abort on any lockout) | Per-user threshold + policy query | Global, per-user, per-host fail limits | Policy query + PSO + badPwdCount | — | badPwdCount + threshold + PSO | Threshold - 3 buffer |
| **Machine-parseable output** | `domain/user:secret@type` | — | JSON, CSV, TXT | Database + log file | — | — | — | CSV |
| **File output** | `-o` flag | `-o` flag + `--hash-file` | `-o` with format choice | `--log` + database | Not implemented (TODO) | — | — | `--output` CSV |
| **Verbosity levels** | 3 (`-v` / `-vv` / `-vvv`) | 1 (`-v`) | 1 (`-v`) | 1 (`-v`) | 2 (`-v` / `-vv`) | — | 2 (`-v` / `-vv`) | Quiet mode only |
| **Post-auth actions** | **None** (by design) | None | None | Extensive (shares, SAM, NTDS, exec, BloodHound) | Domain enum, local admin check | None | BloodHound mark-as-owned | None |
| **Parallel execution** | Sequential | 10 goroutines (default) | Sequential | 256 threads (default) | Sequential | Sequential | Sequential | Sequential |
| **Session resume** | — | — | `--save-state` / `--resume` | Database-driven | — | — | — | `spray_state.json` |
| **Proxy support** | — | — | SOCKS4/5, HTTP, SSH tunnels | — | — | — | — | — |
| **BloodHound integration** | — | — | — | Yes (collection module) | Neo4j: mark-as-owned + path-to-DA | — | Neo4j: mark-as-owned + path-to-DA | — |
| **AD policy query** | — | — | Lockout policy + recommendations | — | Lockout policy + PSO | — | Lockout policy + PSO | — |
| **Test suite** | pytest (unit + integration) | — | — | E2E + database tests | Smoke test only | — | Smoke test only | — |

## Key differentiators

- **CredWolf vs kerbrute** — kerbrute is the closest competitor: fast (Go, goroutines), Kerberos-focused, and widely adopted. However, it only supports passwords — no hashes, no AES/RC4 keys, no ticket files. It has no NTLM support (SMB/LDAP/LDAPS), no paired user:hash or user:key files, no jitter, and no machine-parseable output format. Its `--delay` forces single-threaded execution. CredWolf currently operates sequentially but offers deeper protocol coverage, secret type support, and deterministic error handling.
- **Secret type coverage** — CredWolf is the only tool that supports passwords, NT hashes, RC4 keys, AES128 keys, AES256 keys, and ticket files (ccache/kirbi) with auto-detection, all in a single binary. kerbrute, ADSpray, and pyKerbrute only support passwords (kerbrute) or passwords and NT hashes (ADSpray, pyKerbrute). SmartSpray and SprayHound only support passwords.
- **Credential combination depth** — 88+ permutations of user sources, secret sources, etypes, and transports. No other tool covers the full matrix of NTLM and Kerberos authentication scenarios.
- **Safety-first error model** — CredWolf stops on clock skew (kerbrute logs a warning and continues, risking false negatives), skips users after `KDC_ERR_C_PRINCIPAL_UNKNOWN` / `CLIENT_REVOKED` (kerbrute and others keep trying), and caches AES salts (avoiding extra requests). Each wrong password maps to exactly 1 failed login — no hidden counter inflation.
- **No post-auth scope creep** — tools like NetExec, smartbrute, and SprayHound bundle post-exploitation (share enumeration, SAM dump, BloodHound). This makes them harder to audit, heavier to deploy, and noisier on the wire. CredWolf validates credentials and nothing else.
- **Modern Python** — Python 3.11+ with type annotations, pytest coverage, and CI. pyKerbrute requires Python 2 and PyCrypto (unmaintained). smartbrute self-describes as "more PoC than stable tool".
