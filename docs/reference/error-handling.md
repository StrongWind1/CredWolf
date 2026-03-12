# Error handling

CredWolf handles protocol errors explicitly rather than hiding them. Error descriptions are specific to Windows Active Directory.

## NTLM errors

| Error | Behavior |
|-------|----------|
| `STATUS_LOGON_FAILURE` | Silent — credential is invalid |
| `STATUS_PASSWORD_MUST_CHANGE` | **Reported as valid** — password is correct but must be changed at next logon (`pwdLastSet=0`) |
| `STATUS_PASSWORD_EXPIRED` | **Reported as valid** — password is correct but has expired |
| `STATUS_ACCOUNT_DISABLED` | **Reported as valid** — password is correct, account is disabled |
| `STATUS_ACCOUNT_EXPIRED` | **Reported as valid** — password is correct, account has expired |
| `STATUS_INVALID_LOGON_HOURS` | **Reported as valid** — password is correct, outside allowed logon hours |
| `STATUS_INVALID_WORKSTATION` | **Reported as valid** — password is correct, workstation restriction applies |
| `STATUS_ACCOUNT_RESTRICTION` | Warning — account restriction (e.g., Protected Users group blocks NTLM). Password may or may not be correct. |
| `STATUS_ACCOUNT_LOCKED_OUT` | Warning — account is locked out. Password was not checked by the DC. |
| Other SMB status codes | Displayed as a warning with the raw status code |
| LDAP `strongerAuthRequired` | Automatically retries with LDAPS. If LDAPS also fails, credentials are likely invalid. |
| Connection failure | **Stops execution** — no point retrying if the DC is unreachable |

## Kerberos errors

All Kerberos errors are displayed as `RAW_CODE (human explanation)` with the affected username.

| Error | Code | Behavior |
|-------|------|----------|
| `KDC_ERR_PREAUTH_FAILED` | 0x18 | Silent — wrong password or key |
| `KDC_ERR_KEY_EXPIRED` | 0x17 | **Reported as valid** — the password is correct but expired (`pwdLastSet=0`). Maps to NTLM `STATUS_PASSWORD_MUST_CHANGE` / `STATUS_PASSWORD_EXPIRED`. This confirms the credential. |
| `KDC_ERR_CLIENT_REVOKED` | 0x12 | Warning — account is disabled, expired, locked out, or outside logon hours. Kerberos uses this one error code for all four states; only NTLM distinguishes them (see [mapping table](#ntlm-vs-kerberos-error-mapping) below). Skips subsequent attempts for that user. |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 0x6 | User does not exist in AD. Skips subsequent attempts for that user. |
| `KDC_ERR_POLICY` | 0xC | Warning (indeterminate) — logon restricted by AD policy, typically `SmartcardLogonRequired` flag set on the account. The password may or may not be correct — AD blocks the attempt before checking the credential. |
| `KDC_ERR_NAME_EXP` | 0x1 | Account entry expired in AD. Skips subsequent attempts for that user. |
| `KDC_ERR_CLIENT_NOTYET` | 0x15 | Account not yet valid (future start date in AD). Skips subsequent attempts for that user. |
| `KDC_ERR_NULL_KEY` | 0x9 | No key set on account — password may need to be reset by an admin. Skips subsequent attempts for that user. |
| `KDC_ERR_ETYPE_NOSUPP` | 0xE | The account's `msDS-SupportedEncryptionTypes` or `USE_DES_KEY_ONLY` flag rejects the requested etype. Try a different `--etype`. Does not increment the `--max-lockouts` counter. |
| `KRB_ERR_RESPONSE_TOO_BIG` | 0x34 | AS-REP exceeds UDP datagram size. Retry with `--transport tcp`. |
| `KRB_AP_ERR_SKEW` | 0x25 | **Stops execution** — clock out of sync with KDC. All Kerberos results are unreliable until clocks are synced. Reports the server time if available. |
| `KDC_ERR_WRONG_REALM` | 0x44 | Incorrect domain or principal (typically misconfigured DNS). Skips subsequent attempts for that user. |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | 0x3E | Smart card certificate revoked or untrusted CA. |
| `KRB_ERR_GENERIC` | 0x3C | Generic KDC error — PAC too large, SPN issues, crypto subsystem errors. |
| Connection failure | | **Stops execution** — no point retrying if the KDC is unreachable |

## NTLM vs Kerberos error mapping

Kerberos collapses several distinct account states into fewer error codes. If you need to know the specific reason an account is blocked, test it over NTLM (`credwolf ntlm`).

| NTLM status (specific) | Kerberos error (generic) | AD attribute / cause |
|---|---|---|
| `STATUS_ACCOUNT_DISABLED` | `KDC_ERR_CLIENT_REVOKED` | `userAccountControl` ACCOUNTDISABLE bit or `Enabled=$false` |
| `STATUS_ACCOUNT_EXPIRED` | `KDC_ERR_CLIENT_REVOKED` | `accountExpires` date in the past |
| `STATUS_INVALID_LOGON_HOURS` | `KDC_ERR_CLIENT_REVOKED` | `logonHours` attribute blocks the current time |
| `STATUS_ACCOUNT_LOCKED_OUT` | `KDC_ERR_CLIENT_REVOKED` | Bad-password counter exceeded lockout threshold |
| `STATUS_ACCOUNT_RESTRICTION` | Kerberos succeeds | Protected Users group — NTLM blocked, Kerberos AES works |
| `STATUS_PASSWORD_MUST_CHANGE` | `KDC_ERR_KEY_EXPIRED` | `pwdLastSet=0` (must change at next logon) |
| `STATUS_PASSWORD_EXPIRED` | `KDC_ERR_KEY_EXPIRED` | Password age exceeded `maxPwdAge` |

## Username enumeration error behavior

During `userenum`, only `KDC_ERR_C_PRINCIPAL_UNKNOWN` means the user does not exist. Every other KDC error — including `KDC_ERR_CLIENT_REVOKED`, `KDC_ERR_ETYPE_NOSUPP`, and `KDC_ERR_POLICY` — confirms the user exists because the KDC looked up the principal before returning the error. ASREProastable accounts (pre-authentication not required) return an `AS-REP` instead of an error.
