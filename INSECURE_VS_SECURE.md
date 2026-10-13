# Insecure vs Secure Code (examples used in this project)

Author: Kudzaishe Andrea (H250512W)

## 1. Broken encapsulation
```java
// INSECURE
public class User { public String username; public boolean isAdmin; }
user.isAdmin = true;            // any code can promote itself
```
**Risk:** privilege escalation, no validation, no audit trail.
```java
// SECURE (see User.java, Account.java)
private Role role;                         // private state
void setRole(Role r) { ... }               // package-private: only Bank may call it
public User(...) { validate everything }   // secure constructor
```
**Why safer:** state changes only through code that checks permissions and writes to the audit log.

## 2. Plain-text passwords
```java
// INSECURE
writer.println(username + "|" + password);
// SECURE (PasswordUtil.java)
hash = PBKDF2WithHmacSHA256(password, randomSalt, 120000 iterations);
```
**Risk:** one leaked file exposes every password. **Why safer:** salted slow hashing means stolen hashes are
expensive to crack and identical passwords produce different hashes.

## 3. Missing or blacklist input validation (injection into the data file)
```java
// INSECURE: accepts any text as a username
register("bob|x|y|0|false|ADMIN");   // forges a whole record in a pipe-delimited file
// SECURE (InputValidator.java): whitelist
Pattern.compile("^[a-z0-9_]{3,20}$")
```
**Risk:** record forgery and privilege escalation. **Why safer:** only known-good characters are allowed,
so the delimiter and control characters can never get in. Validation is repeated in `Bank` and in constructors.

## 4. Leaking information in errors
```java
// INSECURE
catch (Exception e) { e.printStackTrace(); }
System.out.println("User 'alice' exists but password is wrong");
// SECURE
throw new AuthenticationException();   // "Invalid credentials, or the account is locked."
```
**Risk:** attackers learn which usernames exist and how the system works. **Why safer:** one safe message;
details go to the audit log (class name only).

## 5. Floating-point money
```java
// INSECURE
double balance = 0.1 + 0.2;   // 0.30000000000000004
// SECURE
BigDecimal balance = new BigDecimal("0.10").add(new BigDecimal("0.20"));   // 0.30
```
**Risk:** rounding errors that can be exploited or cause financial loss.

## 6. Insecure direct object reference (horizontal privilege escalation)
```java
// INSECURE
Account a = accounts.get(accountNumber);   // anyone can use any account number
// SECURE (Bank.ownedAccount)
if (!a.getOwner().equals(session.getUsername())) { log("ACCESS_DENIED"); throw new AccountNotFoundException(); }
```
**Why safer:** customers can only reach their own accounts; the error does not reveal whether the account exists.

## 7. Logging secrets, and logs that can be silently edited
```java
// INSECURE
log.println("login " + username + " password=" + password);
// SECURE (AuditLogger.java)
{"time":"...","event":"LOGIN_FAILED","user":"alice","detail":"wrong password","prev":"<hash>","hash":"<hash>"}
```
**Why safer:** no secrets, escaped values (no log injection), and a hash chain makes tampering detectable.

## 8. Silent failure when saving
```java
// INSECURE
try { save(); } catch (IOException e) { /* ignore */ }   // user thinks it worked
// SECURE (Bank.persist)
catch (StorageException e) { reload(); throw new StorageException(); }   // roll back, tell the user safely
```

## Tools and testing
Each example above has matching tests in `test/SecurityTests.java`. Workflow used: write the insecure version,
write a failing test, fix the code, re-run the tests (all 73 pass). Static checks: `javac -Xlint:all` shows no warnings.
