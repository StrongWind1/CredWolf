# Roadmap

- **Parallel execution** — credential testing is currently sequential. Thread-based or async parallelism would significantly improve speed for large user/password lists, especially over TCP where connection setup dominates.
- **AS-REP hash extraction** — when `userenum` discovers an ASREProastable account (pre-authentication not required), the KDC returns an AS-REP containing encrypted data that can be cracked offline with hashcat (`$krb5asrep$23$`). CredWolf currently flags these accounts but discards the AS-REP. A `--asrep-out` flag would save the hashes in hashcat format.
- **Automatic etype fallback** — when `KDC_ERR_ETYPE_NOSUPP` is returned during credential validation, automatically retry the user with AES256 instead of requiring the operator to re-run with `--etype aes256`. This would catch Protected Users members and DES-only accounts in a single pass.
- **Session resume** — save progress to a state file so interrupted runs can be resumed without re-testing credentials that were already checked. Useful for large credential lists over slow or unstable links.
- **Proxy / SOCKS support** — route connections through SOCKS4/5 or HTTP proxies to support pivoting through compromised hosts. ADSpray already supports this via PySocks.
- **`--realm` override** — allow the Kerberos realm to be set independently of the domain name (currently force-uppercased from `-d`). Would enable testing against non-standard realm configurations.
- **User randomization** — `--randomize` flag to shuffle the user list order per password, reducing the chance of sequential lockouts on adjacent accounts.
