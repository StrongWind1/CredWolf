# Output format

## Credential format

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

## Username enumeration format

Valid usernames are printed as:

```
evil.corp/Administrator
evil.corp/svc_backup — no_preauth (ASREProastable)
evil.corp/Guest — KDC_ERR_CLIENT_REVOKED
```

When writing to a file with `-o`/`--output`, only the `domain/user` portion is written (one per line, no status annotations).

## Username case correction

When Kerberos AES authentication is used, the KDC returns the correct username casing in the ETYPE-INFO2 salt (format `REALMusername`). CredWolf extracts this and automatically corrects the username in all output — console, output file, and logs.

```bash
credwolf -v -d evil.corp kerberos --kdc-ip 10.0.0.1 -u ADMINISTRATOR -P passwords.txt -e aes256 --transport tcp
# [VERBOSE] Username case corrected by KDC: ADMINISTRATOR → Administrator
# [+] evil.corp/Administrator:Password1!@password
```

The corrected casing is also used in the output file. This only applies to Kerberos with AES password authentication (which triggers salt retrieval). NTLM and Kerberos password authentication with RC4 etype use the username as provided.
