# Credential combination matrix

## NTLM (x3 transports: SMB, LDAP, LDAPS)

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 1 | `-u`/`--user` | `-p`/`--password` | 1 attempt |
| 2 | `-u`/`--user` | `-P`/`--passwords-file` | iterate passwords |
| 3 | `-u`/`--user` | `--hash` | 1 attempt |
| 4 | `-u`/`--user` | `-H`/`--hashes-file` | iterate hashes |
| 5 | `-U`/`--users-file` | `-p`/`--password` | password spray |
| 6 | `-U`/`--users-file` | `-P`/`--passwords-file` | cartesian product |
| 7 | `-U`/`--users-file` | `--hash` | hash spray |
| 8 | `-U`/`--users-file` | `-H`/`--hashes-file` | cartesian product |
| 9 | `--user-pass-file` | (user:password embedded) | paired lines |
| 10 | `--user-hash-file` | (user:hash embedded) | paired lines |

All 10 combinations work over each of the 3 transports (**30 total permutations**).

## Kerberos (x2 transports: UDP, TCP)

### Password-based (x3 etypes: RC4, AES128, AES256)

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 1 | `-u`/`--user` | `-p`/`--password` | 1 attempt |
| 2 | `-u`/`--user` | `-P`/`--passwords-file` | iterate passwords |
| 3 | `-U`/`--users-file` | `-p`/`--password` | password spray |
| 4 | `-U`/`--users-file` | `-P`/`--passwords-file` | cartesian product |

4 combinations x 3 etypes x 2 transports = **24 permutations**.

### Inline key-based

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 5 | `-u`/`--user` | `--rc4-key` | 1 attempt |
| 6 | `-u`/`--user` | `--aes128-key` | 1 attempt |
| 7 | `-u`/`--user` | `--aes256-key` | 1 attempt |
| 8 | `-U`/`--users-file` | `--rc4-key` | key spray |
| 9 | `-U`/`--users-file` | `--aes128-key` | key spray |
| 10 | `-U`/`--users-file` | `--aes256-key` | key spray |

Inline keys of different types can be combined (e.g., `--rc4-key X --aes256-key Y`). 6+ combinations x 2 transports = **12+ permutations**.

### Key file-based (files can be combined)

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 11 | `-u`/`-U` | `--rc4-file` | cartesian product |
| 12 | `-u`/`-U` | `--aes128-file` | cartesian product |
| 13 | `-u`/`-U` | `--aes256-file` | cartesian product |
| 14 | `-u`/`-U` | multiple key files combined | pooled cartesian product |

Key files pool into a single list and iterate per user. 8+ combinations x 2 transports = **16+ permutations**.

### Ticket and paired files

| # | User source | Secret source | Iteration strategy |
|---|-------------|---------------|--------------------|
| 15 | `-u`/`--user` | `--ticket` | validate TGT |
| 16 | `-U`/`--users-file` | `--ticket` | validate TGT per user |
| 17 | `--user-key-file` | (user:key embedded, auto-detect) | paired lines |

3 combinations x 2 transports = **6 permutations**.

**Kerberos total: 58+ permutations.** Combined with NTLM: **88+ total permutations.**

## Mutual exclusion rules

**NTLM secret sources** are mutually exclusive (enforced by argparse): `-p`/`--password`, `-P`/`--passwords-file`, `-H`/`--hashes-file`, `--hash`, `--user-pass-file`, `--user-hash-file`.

**Kerberos secret categories** are mutually exclusive (enforced by validation):

- Passwords: `-p`/`--password`, `-P`/`--passwords-file` (also mutually exclusive with each other)
- Inline keys: `--rc4-key`, `--aes128-key`, `--aes256-key` (combinable with each other)
- Key files: `--rc4-file`, `--aes128-file`, `--aes256-file` (combinable with each other)
- Ticket: `--ticket` (ccache or kirbi)
- Paired file: `--user-key-file` (standalone — no `-u`/`-U` allowed)
