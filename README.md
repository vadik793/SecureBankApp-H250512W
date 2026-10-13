# Secure Banking Application

## Description
A console-based banking application written in Java for ISS 2101 Secure Coding. It demonstrates
Object-Oriented Programming and the secure coding techniques covered in the course. All data is stored in plain
text files (no database).

## Student Details
- **Name:** Kudzaishe Andrea
- **Registration Number:** H250512W

## Features
- Registration and login (with optional two-factor authentication)
- Three roles: **Customer**, **Auditor**, **Administrator**
- Customers: create Savings or Current accounts, view balances, deposit, withdraw, view transaction history
- Administrators: list users, unlock locked users, assign roles, view and verify the audit log
- Auditors: read-only access to the audit log and its integrity check
- Data saved to `data/users.txt`, `data/accounts.txt`, `data/transactions.txt` and `data/audit.log`, loaded at start-up

## How to Compile and Run
Requires JDK 17 or later. Run all commands from the project root folder (the folder containing `src` and `data`).
```
mkdir out
javac -d out src/*.java
java -cp out Main
```
**First run:** the first user to register becomes the Administrator (bootstrap rule). Register a second user to
use the customer features. The Administrator can then give a user the Auditor role.

## Running the Unit Tests (73 security-focused tests)
```
javac -cp out -d out test/*.java
java -cp out SecurityTests
```
The tests use an in-memory store, so they never touch your real data files.

## Static Analysis
- `javac -Xlint:all -d out src/*.java` compiles with **zero warnings**.
- Optional: install the VS Code extension **SonarQube for IDE** (previously called SonarLint) to analyse the code
  as you type, or run SpotBugs through Maven/Gradle.

## Where Each Course Concept Is Implemented
| Course concept | Implementation |
|---|---|
| Encapsulation (private fields, controlled access) | `Account`, `User`, `Session`: all fields private, access through methods |
| Abstraction | `DataStore` interface (the program does not care how data is stored); `Bank` exposes a small secure API |
| Inheritance and polymorphism | Abstract `Account` with `SavingsAccount` and `CurrentAccount`; same `withdraw()`, different rule |
| `final` to stop overriding of critical methods | `Account.deposit()`, `withdraw()` are `final`; subclasses are `final` |
| `protected` access | `Account.minimumAllowedBalance()` can be customised only by subclasses |
| Secure constructors and initialisation | `Account`, `User`, `Transaction`, `Session` validate in their constructors |
| Immutable objects | `Transaction` (final class, final fields), `AccountInfo` (record), `Role` permission sets |
| Defensive copying / read-only views | `Bank` returns unmodifiable lists and `AccountInfo` snapshots, never real `Account` objects |
| Secure data types and collections (generics) | Typed `Map<String, User>`, `List<Transaction>`, `EnumSet<Permission>`; `BigDecimal` for money |
| Input validation, whitelisting | `InputValidator` (regex whitelists for usernames, account numbers, amounts) plus re-validation in `Bank` |
| Sanitisation / injection defence | Whitelisting stops the file delimiter `\|` and control characters; `AuditLogger` escapes every value |
| Password hashing and salting | `PasswordUtil`: PBKDF2-HMAC-SHA256, 120,000 iterations, random 16-byte salt, constant-time compare |
| Multi-factor authentication | `Totp` (RFC 6238, works with Google/Microsoft Authenticator) |
| Authentication weaknesses mitigated | Lockout after 3 failures, 1-second throttle, strong password policy, identical error for every failure |
| Session management | `Session` with inactivity timeout (5 minutes) and logout |
| Authorization, RBAC, least privilege | `Role` and `Permission`; `Bank.require()` is called by every operation |
| Separation of duties | Admin manages users but cannot touch customer money; auditor is read-only |
| Privilege escalation prevented | Horizontal: `ownedAccount()` ownership check. Vertical: permission checks, no self role change, ADMIN role never assignable |
| Secure by default / fail-safe defaults | New users are `CUSTOMER`; permissions default to deny; new accounts start at 0.00 |
| Failing securely | Storage errors roll back in-memory changes and show a generic message; a corrupt record is skipped, never trusted |
| Secure error handling and custom exceptions | `BankException` hierarchy with safe messages; unexpected errors show a generic message only |
| Secure logging | `AuditLogger`: structured JSON, timestamps, never logs secrets, escaped values |
| Log integrity / non-repudiation | SHA-256 hash chain; "Verify audit log integrity" detects edits |
| Economy of mechanism (use vetted libraries) | Standard `javax.crypto` and `java.security`; no custom cryptography |
| Defence in depth | Validation in the UI, again in `Bank`, again in the domain classes |
| Threat modelling (STRIDE) | See `THREAT_MODEL.md` |
| Insecure vs secure code examples | See `INSECURE_VS_SECURE.md` |
| Unit and static testing | `test/SecurityTests.java` and the static-analysis section above |

## OWASP Top 10 (2021) Mapping
| Category | Our controls |
|---|---|
| A01 Broken Access Control | RBAC permissions, ownership checks, separation of duties |
| A02 Cryptographic Failures | PBKDF2 with salt; no plain-text passwords |
| A03 Injection | Whitelist validation; delimiter and log-injection protection |
| A04 Insecure Design | Threat model, secure defaults, least privilege |
| A05 Security Misconfiguration | Secure defaults, no stack traces or debug output shown |
| A07 Identification and Authentication Failures | Lockout, MFA, strong passwords, session timeout |
| A08 Software and Data Integrity Failures | Tamper-evident audit log, atomic file writes |
| A09 Security Logging and Monitoring Failures | Audit log of logins, failures, denials, transactions, admin actions |

## Known Limitations (honest notes)
- The text files are not encrypted or signed. Someone with direct file-system access could edit them (for example
  change a role). In production, use file permissions plus a database with proper access control.
- The MFA secret is stored in `users.txt` unencrypted, and a one-time code could be reused within its 30-second window.
- The audit hash chain detects edits and deletions in the middle of the log, but not removal of the very last lines.
- The application is single-user console software with no network layer, so there is no TLS or IP logging.

## File Structure
```
SecureBankApp-H250512W/
├── src/                     (application source code)
├── test/                    (security unit tests)
├── data/                    (users.txt, accounts.txt, transactions.txt, audit.log)
├── THREAT_MODEL.md
├── INSECURE_VS_SECURE.md
├── .gitignore
└── README.md
```
