
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.List;






public class SecurityTests {
    private static int passed = 0, failed = 0;
    private static final char[] PW = "Strong#Pass1".toCharArray();


    private static void check(String name, boolean ok) {
        if (ok) { passed++; System.out.println("  PASS  " + name); }
        else { failed++; System.out.println("  FAIL  " + name); }
    }

    private static boolean throwsType(Class<? extends Throwable> type, Runnable r) {
        try { r.run(); return false; }
        catch (Throwable t) { return type.isInstance(t); }
    }

    private static String messageOf(Runnable r) {
        try { r.run(); return null; } catch (RuntimeException e) { return e.getMessage(); }
    }

    private static void section(String s) { System.out.println("\n" + s); }


    private static Bank newBank(InMemoryStore store) { return new Bank(store); }


    private static Bank setup(InMemoryStore store) {
        Bank b = newBank(store);
        b.register("admin1", PW.clone());
        b.register("alice", PW.clone());
        b.register("bob", PW.clone());
        return b;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== Security unit tests ===");

        section("1. Password storage (hashing + salting)");
        String salt1 = PasswordUtil.generateSalt(), salt2 = PasswordUtil.generateSalt();
        String h1 = PasswordUtil.hash(PW.clone(), salt1);
        check("hash is not the plain-text password", !h1.contains("Strong#Pass1"));
        check("same password + different salt gives different hash", !h1.equals(PasswordUtil.hash(PW.clone(), salt2)));
        check("correct password verifies", PasswordUtil.verify(PW.clone(), salt1, h1));
        check("wrong password is rejected", !PasswordUtil.verify("Wrong#Pass9".toCharArray(), salt1, h1));
        check("password hash never appears in users file as plain text",
                !String.join("", new InMemoryStoreHolder().usersFileAfterRegister()).contains("Strong#Pass1"));

        section("2. Input validation (whitelisting)");
        check("weak passwords are rejected",
                !InputValidator.isStrongPassword("password".toCharArray()) && !InputValidator.isStrongPassword("Ab1!".toCharArray()));
        check("strong password is accepted", InputValidator.isStrongPassword(PW.clone()));
        check("SQL-injection style username rejected", !InputValidator.isValidUsername("alice' OR '1'='1"));
        check("path-traversal username rejected", !InputValidator.isValidUsername("../../etc/passwd"));
        check("username with pipe (file delimiter) rejected", !InputValidator.isValidUsername("a|b|c"));
        check("valid username accepted", InputValidator.isValidUsername("alice_1"));
        check("negative amount rejected", InputValidator.parseAmount("-5") == null);
        check("zero amount rejected", InputValidator.parseAmount("0") == null);
        check("3 decimal places rejected", InputValidator.parseAmount("10.999") == null);
        check("text amount rejected", InputValidator.parseAmount("abc") == null);
        check("amount above the limit rejected", InputValidator.parseAmount("1000000.01") == null);
        check("boundary: exactly the limit is accepted", InputValidator.parseAmount("1000000.00") != null);
        check("malformed account number rejected", !InputValidator.isValidAccountNumber("ACC1; DROP TABLE"));

        section("3. Encapsulation, final methods, secure constructors, polymorphism");
        check("savings account cannot go below zero",
                throwsType(InsufficientFundsException.class, () -> new SavingsAccount("ACC00000001", "alice", BigDecimal.ZERO).withdraw(new BigDecimal("0.01"))));
        Account cur = new CurrentAccount("ACC00000002", "alice", BigDecimal.ZERO);
        cur.withdraw(new BigDecimal("500.00"));
        check("current account may use its 500.00 overdraft", cur.getBalance().compareTo(new BigDecimal("-500.00")) == 0);
        check("current account refuses beyond the overdraft",
                throwsType(InsufficientFundsException.class, () -> cur.withdraw(new BigDecimal("0.01"))));
        check("deposit() is final (cannot be overridden)", Modifier.isFinal(Account.class.getMethod("deposit", BigDecimal.class).getModifiers()));
        check("withdraw() is final (cannot be overridden)", Modifier.isFinal(Account.class.getMethod("withdraw", BigDecimal.class).getModifiers()));
        boolean allPrivate = true;
        for (Field f : Account.class.getDeclaredFields()) if (!Modifier.isPrivate(f.getModifiers())) allPrivate = false;
        check("all Account fields are private", allPrivate);
        check("secure constructor rejects invalid account number",
                throwsType(IllegalArgumentException.class, () -> new SavingsAccount("bad", "alice", BigDecimal.ZERO)));
        check("secure constructor rejects invalid owner",
                throwsType(IllegalArgumentException.class, () -> new SavingsAccount("ACC00000003", "x;y", BigDecimal.ZERO)));
        check("secure constructor rejects a null balance",
                throwsType(IllegalArgumentException.class, () -> new SavingsAccount("ACC00000004", "alice", null)));
        check("Session constructor rejects a null role",
                throwsType(NullPointerException.class, () -> new Session("alice", null, Duration.ofMinutes(1))));

        section("4. Immutability and collections");
        boolean allFinal = Modifier.isFinal(Transaction.class.getModifiers());
        for (Field f : Transaction.class.getDeclaredFields()) if (!Modifier.isFinal(f.getModifiers())) allFinal = false;
        check("Transaction is a final class with only final fields", allFinal);
        check("role permission sets cannot be modified from outside",
                throwsType(UnsupportedOperationException.class, () -> Role.CUSTOMER.getPermissions().add(Permission.MANAGE_USERS)));
        InMemoryStore st = new InMemoryStore();
        Bank b = setup(st);
        Session alice = b.login("alice", PW.clone());
        b.createAccount(alice, "SAVINGS");
        check("account list returned to callers is read-only",
                throwsType(UnsupportedOperationException.class, () -> b.getAccounts(alice).add(new AccountInfo("x", "y", BigDecimal.ZERO))));

        section("5. Role-Based Access Control and privilege escalation");
        Session admin = b.login("admin1", PW.clone());
        check("first registered user is the administrator", admin.getRole() == Role.ADMIN);
        check("later users default to CUSTOMER (secure default)", alice.getRole() == Role.CUSTOMER);
        check("CUSTOMER lacks admin permission, ADMIN lacks banking permission",
                !Role.CUSTOMER.can(Permission.MANAGE_USERS) && !Role.ADMIN.can(Permission.DEPOSIT));
        check("vertical escalation: customer cannot list users", throwsType(UnauthorizedException.class, () -> b.listUsers(alice)));
        check("vertical escalation: customer cannot unlock users", throwsType(UnauthorizedException.class, () -> b.unlockUser(alice, "bob")));
        check("vertical escalation: customer cannot assign roles", throwsType(UnauthorizedException.class, () -> b.assignRole(alice, "alice", "AUDITOR")));
        check("vertical escalation: customer cannot read the audit log", throwsType(UnauthorizedException.class, () -> b.readAuditLog(alice)));
        check("separation of duties: admin cannot open bank accounts", throwsType(UnauthorizedException.class, () -> b.createAccount(admin, "SAVINGS")));
        check("admin cannot assign the ADMIN role", throwsType(InvalidInputException.class, () -> b.assignRole(admin, "alice", "ADMIN")));
        check("admin cannot change their own role", throwsType(UnauthorizedException.class, () -> b.assignRole(admin, "admin1", "CUSTOMER")));
        check("unknown role name rejected", throwsType(InvalidInputException.class, () -> b.assignRole(admin, "alice", "SUPERUSER")));
        b.assignRole(admin, "bob", "AUDITOR");
        Session bob = b.login("bob", PW.clone());
        check("admin can assign the AUDITOR role", bob.getRole() == Role.AUDITOR);
        check("auditor can read and verify the audit log", !b.readAuditLog(bob).isEmpty() && b.verifyAuditLog(bob).startsWith("OK"));
        check("auditor cannot move money", throwsType(UnauthorizedException.class, () -> b.createAccount(bob, "SAVINGS")));
        check("auditor cannot manage users", throwsType(UnauthorizedException.class, () -> b.listUsers(bob)));
        b.assignRole(admin, "bob", "CUSTOMER");
        check("role change takes effect immediately on an existing session",
                throwsType(UnauthorizedException.class, () -> b.readAuditLog(bob)));

        section("6. Horizontal privilege escalation (one customer vs another)");
        Session bob2 = b.login("bob", PW.clone());
        String aliceAcc = b.getAccounts(alice).get(0).number();
        b.deposit(alice, aliceAcc, new BigDecimal("100.00"));
        check("bob cannot deposit into alice's account", throwsType(AccountNotFoundException.class, () -> b.deposit(bob2, aliceAcc, new BigDecimal("1.00"))));
        check("bob cannot withdraw from alice's account", throwsType(AccountNotFoundException.class, () -> b.withdraw(bob2, aliceAcc, new BigDecimal("1.00"))));
        check("bob cannot read alice's history", throwsType(AccountNotFoundException.class, () -> b.history(bob2, aliceAcc)));
        check("error for someone else's account equals error for a non-existent account (no enumeration)",
                java.util.Objects.equals(messageOf(() -> b.history(bob2, aliceAcc)), messageOf(() -> b.history(bob2, "ACC99999999"))));
        check("alice's balance is untouched", b.getAccounts(alice).get(0).balance().compareTo(new BigDecimal("100.00")) == 0);

        section("7. Authentication: lockout, vague errors, sessions");
        InMemoryStore st2 = new InMemoryStore();
        Bank b2 = setup(st2);
        String unknown = messageOf(() -> b2.login("nobody", PW.clone()));
        String wrong = messageOf(() -> b2.login("alice", "Wrong#Pass9".toCharArray()));
        check("unknown user and wrong password give the SAME message", unknown != null && unknown.equals(wrong));
        messageOf(() -> b2.login("alice", "Wrong#Pass9".toCharArray()));
        messageOf(() -> b2.login("alice", "Wrong#Pass9".toCharArray()));
        check("correct password is refused once the account is locked",
                throwsType(AuthenticationException.class, () -> b2.login("alice", PW.clone())));
        check("locked-account message equals the wrong-password message", wrong.equals(messageOf(() -> b2.login("alice", PW.clone()))));
        Session admin2 = b2.login("admin1", PW.clone());
        b2.unlockUser(admin2, "alice");
        check("administrator can unlock; alice can log in again", b2.login("alice", PW.clone()) != null);
        Bank quick = new Bank(new InMemoryStore(), Duration.ofMillis(60));
        quick.register("admin1", PW.clone());
        quick.register("carol", PW.clone());
        Session carol = quick.login("carol", PW.clone());
        Thread.sleep(150);
        check("session expires after inactivity", throwsType(SessionExpiredException.class, () -> quick.createAccount(carol, "SAVINGS")));

        section("8. Multi-factor authentication (TOTP, RFC 6238)");
        check("RFC 6238 test vector (time 59) gives 287082", Totp.codeAt("12345678901234567890".getBytes(), 59).equals("287082"));
        byte[] secret = Totp.newSecret();
        check("Base32 round trip preserves the secret", java.util.Arrays.equals(secret, Totp.fromBase32(Totp.toBase32(secret))));
        long now = Instant.now().getEpochSecond();
        check("current code verifies", Totp.verify(secret, Totp.codeAt(secret, now), now));
        check("wrong code rejected", !Totp.verify(secret, "000000".equals(Totp.codeAt(secret, now)) ? "111111" : "000000", now));
        check("non-digit code rejected", !Totp.verify(secret, "12ab56", now));
        InMemoryStore st3 = new InMemoryStore();
        Bank b3 = setup(st3);
        Session a3 = b3.login("alice", PW.clone());
        String shown = b3.enableMfa(a3);
        check("login without a valid code fails",
                throwsType(AuthenticationException.class, () -> b3.login("alice", PW.clone(), () -> "000000".equals(Totp.codeAt(Totp.fromBase32(shown), Instant.now().getEpochSecond())) ? "111111" : "000000")));
        check("login with the correct code succeeds",
                b3.login("alice", PW.clone(), () -> Totp.codeAt(Totp.fromBase32(shown), Instant.now().getEpochSecond())) != null);
        check("MFA cannot be enabled twice", throwsType(BankException.class, () -> b3.enableMfa(a3)));

        section("9. Secure logging (audit log)");
        InMemoryStore st4 = new InMemoryStore();
        Bank b4 = setup(st4);
        b4.login("alice", PW.clone());
        messageOf(() -> b4.login("alice", "Wrong#Pass9".toCharArray()));
        messageOf(() -> b4.login("x\",\"event\":\"HACKED\nnew line", PW.clone()));
        List<String> log = st4.readLines("audit.log");
        String all = String.join("\n", log);
        check("log never contains a password", !all.contains("Strong#Pass1") && !all.contains("Wrong#Pass9"));
        check("log injection attempt did not forge an event", !all.contains("HACKED"));
        check("every log line is valid structured JSON-style event with timestamp",
                log.stream().allMatch(l -> l.startsWith("{\"time\":\"") && l.contains("\"event\":\"") && l.endsWith("\"}")));
        Session adm4 = b4.login("admin1", PW.clone());
        check("untouched log verifies as OK", b4.verifyAuditLog(adm4).startsWith("OK"));
        st4.replaceLine("audit.log", 1, log.get(1).replace("REGISTER", "LOGIN_OK"));
        check("tampering with a log entry is detected", b4.verifyAuditLog(adm4).startsWith("TAMPERED"));

        section("10. Failing securely");
        InMemoryStore st5 = new InMemoryStore();
        Bank b5 = setup(st5);
        Session a5 = b5.login("alice", PW.clone());
        String acc5 = b5.createAccount(a5, "SAVINGS").number();
        b5.deposit(a5, acc5, new BigDecimal("50.00"));
        st5.failWrites = true;
        check("storage failure during a deposit raises a safe, generic error",
                "Storage error. The operation could not be completed.".equals(messageOf(() -> b5.deposit(a5, acc5, new BigDecimal("25.00")))));
        st5.failWrites = false;
        check("failed deposit was rolled back (balance unchanged)", b5.getAccounts(a5).get(0).balance().compareTo(new BigDecimal("50.00")) == 0);
        check("error messages never expose exception class names or paths",
                !String.valueOf(messageOf(() -> b5.history(a5, "ACC00000000"))).contains("Exception")
                        && !String.valueOf(messageOf(() -> b5.deposit(a5, acc5, BigDecimal.TEN.negate()))).contains("."+"java"));

        System.out.println("\n=== Result: " + passed + " passed, " + failed + " failed ===");
        if (failed > 0) System.exit(1);
    }


    private static final class InMemoryStoreHolder {
        List<String> usersFileAfterRegister() {
            InMemoryStore s = new InMemoryStore();
            new Bank(s).register("dave", PW.clone());
            return s.readLines("users.txt");
        }
    }
}
