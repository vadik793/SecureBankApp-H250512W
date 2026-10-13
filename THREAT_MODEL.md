# Threat Model (STRIDE)

**Application:** Secure Banking Application | **Author:** Kudzaishe Andrea (H250512W)

## 1. Decompose the application
- **Assets:** user credentials (hashes), MFA secrets, account balances, transaction history, audit log.
- **Entry points:** console input (menus, usernames, passwords, amounts, account numbers, MFA codes) and the data files.
- **Trust boundaries:** (1) user input to application, (2) application to the file system.
- **Actors:** Customer, Auditor, Administrator, and an attacker (anonymous user, malicious customer, or someone with file access).

## 2. Identify and mitigate threats
| STRIDE | Threat in this application | Mitigation | Where |
|---|---|---|---|
| **S**poofing | Guessing or stealing a password to log in as someone else | PBKDF2 + salt, strong password policy, lockout after 3 failures, 1-second throttle, optional TOTP MFA, identical error for every failure | `PasswordUtil`, `Bank.login`, `Totp` |
| **S**poofing | Finding valid usernames through different error messages | One vague message for unknown user, wrong password and locked account; same hashing work for unknown users | `AuthenticationException`, `Bank.login` |
| **T**ampering | Injecting `\|` or newlines in input to forge records in the text files | Whitelist validation of every field; fields validated again in constructors | `InputValidator`, `User`, `Account` |
| **T**ampering | Changing amounts or balances through bad input | Positive amounts, 2 decimals, upper limit, `BigDecimal`, `final` deposit/withdraw | `InputValidator`, `Account` |
| **T**ampering | Editing the audit log to hide actions | SHA-256 hash chain, verification feature | `AuditLogger` |
| **T**ampering | Half-written file after a crash | Write to a temp file then atomic replace | `FileStorage` |
| **R**epudiation | A user denies a deposit, withdrawal or admin action | Timestamped, structured audit entries for logins, failures, transactions, role changes | `AuditLogger`, `Bank` |
| **I**nformation disclosure | Error messages leaking internals | Custom exceptions with safe messages; unexpected errors show only a generic message | `BankException` hierarchy, `Main` |
| **I**nformation disclosure | Passwords or secrets in logs | Logger never receives passwords; passwords held as `char[]` and wiped after use | `AuditLogger`, `Main` |
| **I**nformation disclosure | Reading another customer's account | Ownership check; same error for "not yours" and "does not exist" | `Bank.ownedAccount` |
| **D**enial of service | Brute-force attempts lock real users | Lockout is per account and an administrator can unlock; throttle slows guessing | `Bank`, `User` |
| **D**enial of service | Huge or invalid inputs, storage failure | Length and range limits; storage failures roll back and fail securely | `InputValidator`, `Bank.persist` |
| **E**levation of privilege | A customer calls admin functions | Every operation calls `require(session, permission)`; default deny | `Bank.require`, `Role` |
| **E**levation of privilege | An admin promotes themselves or others to ADMIN | Cannot change own role; ADMIN can never be assigned | `Bank.assignRole` |
| **E**levation of privilege | Using an old session after a role change or after leaving | Role is read from the user store on every request; sessions expire after 5 minutes of inactivity | `Bank.require`, `Session` |

## 3. Residual risks (accepted)
Direct editing of the data files, the unencrypted MFA secret, and one-time-code replay within 30 seconds
(see "Known Limitations" in `README.md`).

## 4. Validate and review
Each mitigation above has at least one automated test in `test/SecurityTests.java`. The model should be
revisited whenever a feature is added (for example transfers between accounts or a network interface).
