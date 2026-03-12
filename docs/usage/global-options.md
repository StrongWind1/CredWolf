# Global options

Options that apply to all subcommands (`ntlm`, `kerberos`, `userenum`).

## Output file

```bash
# Write valid credentials to a file
credwolf -d evil.corp -o results.txt ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt
```

## Verbosity

```bash
# Verbose output (-v), debug output (-vv), or trace (-vvv)
credwolf -v -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'
credwolf -vv -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --transport tcp
```

## Stop on first success

```bash
credwolf --stop-on-success -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -H hashes.txt
```

## Rate limiting

```bash
# Add delay between attempts (seconds) with optional jitter
credwolf --delay 1.5 -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt
credwolf --delay 2 --jitter 0.5 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```

## Connection timeout

```bash
# Custom connection timeout (default: 15s; 0 = no timeout / infinite wait)
credwolf --timeout 60 -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt
credwolf --timeout 0 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```

## Lockout safety

```bash
# Stop after N consecutive revoked accounts (disabled/expired/locked out)
credwolf --max-lockouts 3 -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```
