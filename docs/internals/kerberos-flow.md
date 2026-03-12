# Kerberos authentication flow and account lockout

## Requests per credential type

| Credential type | KDC requests | Counts as login attempt? |
|----------------|-------------|--------------------------|
| Password (RC4 etype) | 1 AS-REQ with encrypted timestamp | Yes — 1 attempt |
| Password (AES128/AES256 etype) | 1 bare AS-REQ (salt retrieval) + 1 AS-REQ with encrypted timestamp | Only the 2nd counts — 1 attempt |
| Raw key (RC4/AES128/AES256) | 1 AS-REQ with encrypted timestamp | Yes — 1 attempt |
| Ticket file (ccache/kirbi) | 1 TGS-REQ | No — not a password attempt |
| Username enumeration | 1 bare AS-REQ (no pre-auth data) | No — not a login attempt |

## How it works

Kerberos pre-authentication proves knowledge of a user's key by encrypting the current timestamp with it. The KDC decrypts the timestamp — if it succeeds, the credential is valid (AS-REP returned). If it fails, `KDC_ERR_PREAUTH_FAILED` is returned and the bad-password counter increments by one.

**AES salt retrieval is harmless.** AES key derivation requires a per-user salt from the KDC. CredWolf obtains this by sending an AS-REQ with no authentication data. The KDC responds with `KDC_ERR_PREAUTH_REQUIRED` and the salt — this is standard protocol behavior, not a login attempt. The salt is cached per user, so this only happens once regardless of how many passwords are tested against the same user.

**Each wrong password/key = exactly 1 failed login.** The mapping is 1:1 — no hidden extra requests that inflate the bad-password counter. This is the same as typing a wrong password interactively.

**Ticket validation does not touch the password counter.** The `--ticket` flag sends a TGS-REQ (not an AS-REQ), which validates the TGT without any password involvement.

## Lockout mitigation

Use `--delay` and `--jitter` to space out attempts when testing against accounts with lockout policies:

```bash
# 2-second delay with 0.5s random jitter between each attempt
credwolf --delay 2 --jitter 0.5 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp

# Stop after the first valid credential (minimizes total attempts)
credwolf --stop-on-success -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp

# Stop after 3 consecutive revoked accounts (likely means the scan is causing lockouts)
credwolf --max-lockouts 3 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```

## Note on `KDC_ERR_CLIENT_REVOKED`

This Kerberos error code does not distinguish between accounts that are disabled, expired, locked out, or outside their allowed logon hours. CredWolf reports all four possibilities in the warning message. The `--max-lockouts` flag counts consecutive `CLIENT_REVOKED` responses — if your scan triggers N in a row, it is likely that the scan itself is causing lockouts rather than encountering pre-existing disabled/expired accounts. To determine the specific cause, test the affected accounts over NTLM (`credwolf ntlm`).
