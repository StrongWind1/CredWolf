# Hash and key formats

## NTLM hashes

Used with `--hash`, `-H`/`--hashes-file`, and `--user-hash-file` (NTLM subcommand only). For Kerberos, use `--rc4-key` instead — the NT hash value is the same as the RC4 key.

Each value is either a bare NT hash or an LM:NT pair. LM hashes are accepted as input but never shown in output — only the NT hash is displayed.

```
7facdc498ed1680c4fd1448319a8c04f
aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
```

Both formats can be mixed in the same file. Invalid lines are skipped with a warning.

## Kerberos keys

| Type | Bytes | Hex chars | Inline flag | File flag |
|------|-------|-----------|-------------|-----------|
| RC4 | 16 | 32 | `--rc4-key` | `--rc4-file` |
| AES128 | 16 | 32 | `--aes128-key` | `--aes128-file` |
| AES256 | 32 | 64 | `--aes256-key` | `--aes256-file` |

## RC4/AES128 ambiguity

RC4 and AES128 keys are both 32 hex characters and cannot be distinguished by length. The `--user-key-file` auto-detection defaults 32-char keys to RC4. To treat them as AES128 instead, pass `-e aes128`:

```bash
# 32-hex keys treated as RC4 (default)
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt --transport tcp

# 32-hex keys treated as AES128
credwolf -d evil.corp kerberos --kdc-ip 10.0.0.1 --user-key-file pairs.txt -e aes128 --transport tcp
```

64-hex keys are always AES256 regardless of `--etype`.
