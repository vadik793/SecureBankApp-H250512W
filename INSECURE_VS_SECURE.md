# Insecure vs Secure Code (examples used in this project)

Author: Kudzaishe Andrea (H250512W)

## 1. Broken encapsulation
```java

public class User { public String username; public boolean isAdmin; }
user.isAdmin = true;
```
**Risk:** privilege escalation, no validation, no audit trail.
```java

private Role role;
void setRole(Role r) { ... }
public User(...) { validate everything }
```
**Why safer:** state changes only through code that checks permissions and writes to the audit log.

## 2. Plain-text passwords
```java

writer.println(username + "|" + password);

hash = PBKDF2WithHmacSHA256(password, randomSalt, 120000 iterations);
```
**Risk:** one leaked file exposes every password. **Why safer:** salted slow hashing means stolen hashes are
expensive to crack and identical passwords produce different hashes.

## 3. Missing or blacklist input validation (injection into the data file)
```java

register("bob|x|y|0|false|ADMIN");

Pattern.compile("^[a-z0-9_]{3,20}$")
```
**Risk:** record forgery and privilege escalation. **Why safer:** only known-good characters are allowed,
so the delimiter and control characters can never get in. Validation is repeated in `Bank` and in constructors.

## 4. Leaking information in errors
```java

catch (Exception e) { e.printStackTrace(); }
System.out.println("User 'alice' exists but password is wrong");

throw new AuthenticationException();
```
**Risk:** attackers learn which usernames exist and how the system works. **Why safer:** one safe message;
details go to the audit log (class name only).

## 5. Floating-point money
```java

double balance = 0.1 + 0.2;

BigDecimal balance = new BigDecimal("0.10").add(new BigDecimal("0.20"));
```
**Risk:** rounding errors that can be exploited or cause financial loss.

## 6. Insecure direct object reference (horizontal privilege escalation)
```java

Account a = accounts.get(accountNumber);

if (!a.getOwner().equals(session.getUsername())) { log("ACCESS_DENIED"); throw new AccountNotFoundException(); }
```
**Why safer:** customers can only reach their own accounts; the error does not reveal whether the account exists.

## 7. Logging secrets, and logs that can be silently edited
```java

log.println("login " + username + " password=" + password);

{"time":"...","event":"LOGIN_FAILED","user":"alice","detail":"wrong password","prev":"<hash>","hash":"<hash>"}
```
**Why safer:** no secrets, escaped values (no log injection), and a hash chain makes tampering detectable.

## 8. Silent failure when saving
```java

try { save(); } catch (IOException e) {  }

catch (StorageException e) { reload(); throw new StorageException(); }
```

## Tools and testing
Each example above has matching tests in `test/SecurityTests.java`. Workflow used: write the insecure version,
write a failing test, fix the code, re-run the tests (all 73 pass). Static checks: `javac -Xlint:all` shows no warnings.
