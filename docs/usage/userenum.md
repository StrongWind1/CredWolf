# Username enumeration

Discover valid AD usernames via Kerberos. This sends bare AS-REQs without pre-authentication — it does not cause login attempts and does not increment the bad-password counter. See [error behavior](#how-it-works) below for how different KDC responses are interpreted.

## Examples

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

## Output

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

## How it works

During `userenum`, only `KDC_ERR_C_PRINCIPAL_UNKNOWN` means the user does not exist. Every other KDC error — including `KDC_ERR_CLIENT_REVOKED`, `KDC_ERR_ETYPE_NOSUPP`, and `KDC_ERR_POLICY` — confirms the user exists because the KDC looked up the principal before returning the error. ASREProastable accounts (pre-authentication not required) return an `AS-REP` instead of an error.
