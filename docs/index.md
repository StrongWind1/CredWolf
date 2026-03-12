<p align="center">
  <img src="assets/credwolf_banner.png" alt="CredWolf" width="800">
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/CredWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/CredWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%E2%80%933.14-blue.svg" alt="Python 3.11+"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

# CredWolf

Credential validation tool for Active Directory Domain Services.

CredWolf tests username and secret combinations (passwords, NT hashes, Kerberos keys, or ticket files) against a domain controller and reports which credentials are valid. It also supports username enumeration via Kerberos to discover valid AD accounts without causing login attempts. It is designed for authorized penetration testing, red team engagements, and security audits where you need to verify whether recovered or suspected credentials are active.

## Features

- **NTLM + Kerberos** — validate credentials over SMB, LDAP, LDAPS, and Kerberos pre-authentication (UDP/TCP)
- **Every secret type** — passwords, NT hashes (bare + LM:NT), RC4 keys, AES128 keys, AES256 keys, and ticket files (ccache/kirbi with auto-detection)
- **Username enumeration** — discover valid AD accounts via Kerberos without triggering login failures or lockouts; ASREProastable accounts flagged automatically
- **Username case correction** — when using Kerberos AES authentication, the KDC returns the correct username casing in the salt. CredWolf detects this and uses the corrected name in all output (console, file, and logs)
- **88+ credential permutations** — every meaningful combination of user sources, secret sources, encryption types, and transports
- **Paired files** — user:password, user:hash, and user:key files for pre-matched credential testing
- **Machine-parseable output** — `domain/user:secret@type` format, easy to grep or pipe
- **Safety-first errors** — clock skew stops execution immediately, per-user skip on unknown/revoked principals, detailed [account status detection](reference/error-handling.md)
- **Rate limiting** — `--delay`, `--jitter`, and `--max-lockouts` to avoid triggering lockout policies
- **Validation only** — no post-authentication activity by design

## Quick start

```bash
pip install credwolf
# or
pipx install credwolf
# or
uv tool install credwolf
```

```bash
# Validate a password over SMB
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'
# [+] evil.corp/Administrator:Password1!@password

# Validate an NT hash (pass-the-hash)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# Validate an AES256 key over Kerberos (pass-the-key)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
# [+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key

# Enumerate valid usernames (no login attempts, no lockout risk)
credwolf -d evil.corp userenum --kdc-ip 10.0.0.1 -U users.txt
# [+] evil.corp/Administrator
# [+] evil.corp/svc_backup — no_preauth (ASREProastable)
# [*] Enumeration complete: 2/5 users found
```

The `cw` command is also installed as a shorthand for `credwolf`.

See the [installation guide](getting-started/installation.md) for source and Docker options, or jump to the full [usage examples](usage/ntlm.md) and [CLI reference](reference/cli.md).

## Supported protocols

| Protocol | Transport | Secret types |
|----------|-----------|--------------|
| **NTLM** | SMB (default), LDAP, LDAPS | Password, NT hash |
| **Kerberos** | UDP (default), TCP | Password, RC4 key, AES128 key, AES256 key, ticket (ccache/kirbi) |

## Disclaimer

CredWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before testing credentials against any Active Directory environment. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

Built on [Impacket](https://github.com/fortra/impacket). Inspired by [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), [Kerbrute](https://github.com/ropnop/kerbrute), [smartbrute](https://github.com/ShutdownRepo/smartbrute), and [SprayHound](https://github.com/Hackndo/sprayhound).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
