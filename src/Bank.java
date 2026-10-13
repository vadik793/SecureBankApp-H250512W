
import java.math.BigDecimal;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Supplier;










public class Bank {
    public static final int MAX_FAILED_ATTEMPTS = 3;
    private static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(5);
    private static final String USERS = "users.txt";
    private static final String ACCOUNTS = "accounts.txt";
    private static final String TRANSACTIONS = "transactions.txt";

    private final DataStore store;
    private final AuditLogger audit;
    private final Duration sessionTimeout;
    private final Map<String, User> users = new HashMap<>();
    private final Map<String, Account> accounts = new LinkedHashMap<>();
    private final List<Transaction> transactions = new ArrayList<>();
    private final SecureRandom random = new SecureRandom();

    public Bank(DataStore store) { this(store, DEFAULT_TIMEOUT); }

    public Bank(DataStore store, Duration sessionTimeout) {
        this.store = store;
        this.audit = new AuditLogger(store);
        this.sessionTimeout = sessionTimeout;
        load();
    }



    private void load() {
        Map<String, User> u = new HashMap<>();
        Map<String, Account> a = new LinkedHashMap<>();
        List<Transaction> t = new ArrayList<>();
        for (String l : store.readLines(USERS)) {
            try { User x = User.fromFileLine(l); u.put(x.getUsername(), x); }
            catch (RuntimeException e) { System.out.println("Skipped a corrupt user record."); }
        }
        for (String l : store.readLines(ACCOUNTS)) {
            try { Account x = Account.fromFileLine(l); a.put(x.getAccountNumber(), x); }
            catch (RuntimeException e) { System.out.println("Skipped a corrupt account record."); }
        }
        for (String l : store.readLines(TRANSACTIONS)) {
            try { t.add(Transaction.fromFileLine(l)); }
            catch (RuntimeException e) { System.out.println("Skipped a corrupt transaction record."); }
        }
        users.clear(); users.putAll(u);
        accounts.clear(); accounts.putAll(a);
        transactions.clear(); transactions.addAll(t);
    }

    private void saveUsers() {
        List<String> l = new ArrayList<>();
        for (User u : users.values()) l.add(u.toFileLine());
        store.writeLines(USERS, l);
    }

    private void saveAccounts() {
        List<String> l = new ArrayList<>();
        for (Account a : accounts.values()) l.add(a.toFileLine());
        store.writeLines(ACCOUNTS, l);
    }

    private void saveTransactions() {
        List<String> l = new ArrayList<>();
        for (Transaction t : transactions) l.add(t.toFileLine());
        store.writeLines(TRANSACTIONS, l);
    }


    private void persist(Runnable save) {
        try {
            save.run();
        } catch (StorageException e) {
            try { load(); } catch (RuntimeException ignored) {  }
            throw new StorageException();
        }
    }






    public Role register(String username, char[] password) {
        username = normalise(username);
        if (!InputValidator.isValidUsername(username))
            throw new InvalidInputException("Username must be 3-20 characters: letters, digits or underscore.");
        if (!InputValidator.isStrongPassword(password))
            throw new InvalidInputException("Password must be 8-64 characters with upper, lower, digit and special character.");
        if (users.containsKey(username)) throw new BankException("Username is not available.");
        Role role = users.isEmpty() ? Role.ADMIN : Role.CUSTOMER;
        String salt = PasswordUtil.generateSalt();
        users.put(username, new User(username, salt, PasswordUtil.hash(password, salt), 0, false, role, "-"));
        try {
            persist(this::saveUsers);
        } catch (StorageException e) {
            users.remove(username);
            throw e;
        }
        audit.log("REGISTER", username, "role=" + role);
        return role;
    }

    public Session login(String username, char[] password) {
        return login(username, password, () -> "");
    }





    public Session login(String username, char[] password, Supplier<String> otpSupplier) {
        username = normalise(username);
        User u = users.get(username);
        String logName = InputValidator.isValidUsername(username) ? username : "<invalid>";
        if (u == null) {
            PasswordUtil.hash(password, PasswordUtil.generateSalt());
            audit.log("LOGIN_FAILED", logName, "unknown user");
            throttle();
            throw new AuthenticationException();
        }
        if (u.isLocked()) {
            audit.log("LOGIN_BLOCKED", logName, "account locked");
            throttle();
            throw new AuthenticationException();
        }
        if (!PasswordUtil.verify(password, u.getSalt(), u.getPasswordHash())) {
            failedLogin(u, logName, "wrong password");
        }
        if (u.hasMfa()) {
            String code = otpSupplier.get();
            if (!Totp.verify(Totp.fromBase32(u.getMfaSecret()), code, Instant.now().getEpochSecond())) {
                failedLogin(u, logName, "wrong MFA code");
            }
        }
        u.resetFailures();
        saveUsers();
        audit.log("LOGIN_SUCCESS", logName, "role=" + u.getRole() + (u.hasMfa() ? " mfa=yes" : ""));
        return new Session(u.getUsername(), u.getRole(), sessionTimeout);
    }

    private void failedLogin(User u, String logName, String reason) {
        u.recordFailure(MAX_FAILED_ATTEMPTS);
        saveUsers();
        audit.log("LOGIN_FAILED", logName, reason);
        if (u.isLocked()) audit.log("ACCOUNT_LOCKED", logName, "too many failed attempts");
        throttle();
        throw new AuthenticationException();
    }

    public void logout(Session s) {
        if (s != null) audit.log("LOGOUT", s.getUsername(), "-");
    }


    private void throttle() {
        try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String normalise(String s) { return s == null ? "" : s.trim().toLowerCase(Locale.ROOT); }


    public void checkSession(Session s) {
        if (s == null || s.isExpired()) {
            if (s != null) audit.log("SESSION_EXPIRED", s.getUsername(), "inactivity timeout");
            throw new SessionExpiredException();
        }
        s.touch();
    }





    private void require(Session s, Permission p) {
        checkSession(s);
        User u = users.get(s.getUsername());
        if (u == null || !u.getRole().can(p)) {
            audit.log("ACCESS_DENIED", s.getUsername(), "missing permission " + p);
            throw new UnauthorizedException();
        }
    }

    private Account ownedAccount(Session s, String accNo) {
        if (!InputValidator.isValidAccountNumber(accNo)) throw new AccountNotFoundException();
        Account a = accounts.get(accNo);
        if (a == null) throw new AccountNotFoundException();
        if (!a.getOwner().equals(s.getUsername())) {
            audit.log("ACCESS_DENIED", s.getUsername(), "tried to access another user's account");
            throw new AccountNotFoundException();
        }
        return a;
    }


    public AccountInfo createAccount(Session s, String type) {
        require(s, Permission.CREATE_ACCOUNT);
        if (!InputValidator.isValidAccountType(type)) throw new InvalidInputException("Account type must be SAVINGS or CURRENT.");
        String number;
        do {
            number = String.format("ACC%08d", random.nextInt(100_000_000));
        } while (accounts.containsKey(number));
        Account a = Account.create(type, number, s.getUsername(), new BigDecimal("0.00"));
        accounts.put(number, a);
        persist(this::saveAccounts);
        audit.log("ACCOUNT_CREATED", s.getUsername(), number + " " + type);
        return a.toInfo();
    }


    public List<AccountInfo> getAccounts(Session s) {
        require(s, Permission.VIEW_BALANCE);
        List<AccountInfo> out = new ArrayList<>();
        for (Account a : accounts.values()) if (a.getOwner().equals(s.getUsername())) out.add(a.toInfo());
        return Collections.unmodifiableList(out);
    }

    public BigDecimal deposit(Session s, String accNo, BigDecimal amount) {
        require(s, Permission.DEPOSIT);
        if (!InputValidator.isValidAmount(amount)) throw new InvalidInputException("Invalid amount.");
        Account a = ownedAccount(s, accNo);
        a.deposit(amount);
        transactions.add(new Transaction(accNo, Transaction.Type.DEPOSIT, amount, a.getBalance(), LocalDateTime.now()));
        persist(() -> { saveAccounts(); saveTransactions(); });
        audit.log("DEPOSIT", s.getUsername(), accNo + " amount=" + amount.toPlainString());
        return accounts.get(accNo).getBalance();
    }

    public BigDecimal withdraw(Session s, String accNo, BigDecimal amount) {
        require(s, Permission.WITHDRAW);
        if (!InputValidator.isValidAmount(amount)) throw new InvalidInputException("Invalid amount.");
        Account a = ownedAccount(s, accNo);
        try {
            a.withdraw(amount);
        } catch (InsufficientFundsException e) {
            audit.log("WITHDRAW_REFUSED", s.getUsername(), accNo + " insufficient funds");
            throw e;
        }
        transactions.add(new Transaction(accNo, Transaction.Type.WITHDRAW, amount, a.getBalance(), LocalDateTime.now()));
        persist(() -> { saveAccounts(); saveTransactions(); });
        audit.log("WITHDRAW", s.getUsername(), accNo + " amount=" + amount.toPlainString());
        return accounts.get(accNo).getBalance();
    }

    public List<String> history(Session s, String accNo) {
        require(s, Permission.VIEW_HISTORY);
        ownedAccount(s, accNo);
        List<String> out = new ArrayList<>();
        for (Transaction t : transactions) if (t.getAccountNumber().equals(accNo)) out.add(t.toString());
        return Collections.unmodifiableList(out);
    }



    public String enableMfa(Session s) {
        require(s, Permission.ENABLE_MFA);
        User u = users.get(s.getUsername());
        if (u.hasMfa()) throw new BankException("Two-factor authentication is already enabled.");
        String secret = Totp.toBase32(Totp.newSecret());
        u.setMfaSecret(secret);
        try {
            persist(this::saveUsers);
        } catch (StorageException e) {
            u.setMfaSecret("-");
            throw e;
        }
        audit.log("MFA_ENABLED", s.getUsername(), "-");
        return secret;
    }


    public List<String> listUsers(Session s) {
        require(s, Permission.MANAGE_USERS);
        List<String> out = new ArrayList<>();
        for (User u : new TreeMap<>(users).values())
            out.add(u.getUsername() + "  [" + u.getRole() + "]" + (u.hasMfa() ? "  MFA" : "") + (u.isLocked() ? "  LOCKED" : ""));
        return out;
    }

    public void unlockUser(Session s, String username) {
        require(s, Permission.MANAGE_USERS);
        User u = users.get(normalise(username));
        if (u == null) throw new BankException("User not found.");
        u.unlock();
        saveUsers();
        audit.log("ADMIN_UNLOCK", s.getUsername(), "unlocked " + u.getUsername());
    }





    public void assignRole(Session s, String username, String roleName) {
        require(s, Permission.ASSIGN_ROLES);
        if (!"CUSTOMER".equals(roleName) && !"AUDITOR".equals(roleName))
            throw new InvalidInputException("Only the roles CUSTOMER or AUDITOR can be assigned.");
        User u = users.get(normalise(username));
        if (u == null) throw new BankException("User not found.");
        if (u.getUsername().equals(s.getUsername())) {
            audit.log("ACCESS_DENIED", s.getUsername(), "tried to change own role");
            throw new UnauthorizedException();
        }
        if (u.getRole() == Role.ADMIN) throw new UnauthorizedException();
        Role previous = u.getRole();
        u.setRole(Role.valueOf(roleName));
        try {
            persist(this::saveUsers);
        } catch (StorageException e) {
            u.setRole(previous);
            throw e;
        }
        audit.log("ROLE_ASSIGNED", s.getUsername(), u.getUsername() + " -> " + roleName);
    }


    public List<String> readAuditLog(Session s) {
        require(s, Permission.VIEW_AUDIT_LOG);
        audit.log("AUDIT_VIEWED", s.getUsername(), "-");
        return audit.readAll();
    }

    public String verifyAuditLog(Session s) {
        require(s, Permission.VERIFY_AUDIT_LOG);
        return audit.verify();
    }



    public void logUnexpected(String user, Exception e) {
        try { audit.log("ERROR", user, e.getClass().getSimpleName()); } catch (RuntimeException ignored) {  }
    }
}
