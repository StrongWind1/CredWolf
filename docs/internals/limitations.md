# Known limitations

## ASREProastable users + AES password + wrong username case

When a user has pre-authentication disabled (ASREProastable), the KDC returns an AS-REP instead of `KDC_ERR_PREAUTH_REQUIRED` during salt retrieval. This means no ETYPE-INFO2 data is available to extract the correct username casing. CredWolf synthesizes a default salt using `REALM + username_as_typed`. Since AES salt is case-sensitive, if the input case doesn't match AD (e.g., `USER1` vs `user1`), the derived key will be wrong and the password will be reported as invalid even if correct.

**Workaround:** use the correct username casing, or use `-e rc4` (RC4 doesn't use salt). This does not affect NTLM, Kerberos with raw keys, or non-ASREProastable accounts (whose correct case is extracted from ETYPE-INFO2 automatically).

## UDP response size

Kerberos over UDP may produce `KRB_ERR_RESPONSE_TOO_BIG` for some users. Use `--transport tcp` as a workaround.

## Clock skew

Clock skew between the client and KDC causes `KRB_AP_ERR_SKEW`. Sync your system clock before running Kerberos authentication.

## RC4/AES128 key ambiguity

AES128 and RC4 Kerberos keys share the same hex length (32 chars). Auto-detection in `--user-key-file` defaults to RC4; use `-e aes128` to override.

## LDAPS availability

LDAPS transport requires the domain controller to have a valid TLS certificate configuration. Connection resets typically indicate LDAPS is not available on the target.

## LM hashes

LM hashes are accepted as input (for compatibility with hash dumps) but are not used for authentication or shown in output. Only the NT hash portion is used.

## Lockout policy discovery

No ability to query the domain's lockout policy or fine-grained password policies (PSOs) directly. Operators must determine safe thresholds externally.
