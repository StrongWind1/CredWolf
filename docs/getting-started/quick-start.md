# Quick start

```bash
# Validate a password over SMB
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'
# [+] evil.corp/Administrator:Password1!@password

# Validate an NT hash over SMB (pass-the-hash)
credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator --hash 7facdc498ed1680c4fd1448319a8c04f
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@nt_hash

# Validate an AES256 key over Kerberos (pass-the-key)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --aes256-key 9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925 --transport tcp
# [+] evil.corp/Administrator:9b12da6a4bdc263c1ac8f6302dc071e6e84321a263fa48784534b1ae43db2925@aes256_key

# Validate an NT hash as RC4 key over Kerberos (overpass-the-hash)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --rc4-key 7facdc498ed1680c4fd1448319a8c04f --transport tcp
# [+] evil.corp/Administrator:7facdc498ed1680c4fd1448319a8c04f@rc4_key

# Enumerate valid usernames (no login attempts, no lockout risk)
credwolf -d evil.corp userenum --kdc-ip 10.0.0.1 -U users.txt
# [+] evil.corp/Administrator
# [+] evil.corp/svc_backup — no_preauth (ASREProastable)
# [*] Enumeration complete: 2/5 users found
```

See the full [NTLM](../usage/ntlm.md), [Kerberos](../usage/kerberos.md), and [username enumeration](../usage/userenum.md) usage guides for all options.
