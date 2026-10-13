// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.util.Objects;

/**
 * A bank user. Only the salted password hash is kept. Secure constructor: input is validated at creation, so an
 * invalid User can never exist. setRole/setMfaSecret are PACKAGE-PRIVATE: only Bank (same package) can call them.
 */
public class User {
    private final String username;
    private final String salt;
    private final String passwordHash;
    private Role role;
    private int failedAttempts;
    private boolean locked;
    private String mfaSecret; // Base32, or "-" when MFA is not enabled

    public User(String username, String salt, String passwordHash, int failedAttempts, boolean locked, Role role, String mfaSecret) {
        if (!InputValidator.isValidUsername(username)) throw new IllegalArgumentException("Invalid username");
        if (failedAttempts < 0) throw new IllegalArgumentException("Invalid attempts");
        this.username = username;
        this.salt = Objects.requireNonNull(salt);
        this.passwordHash = Objects.requireNonNull(passwordHash);
        this.failedAttempts = failedAttempts;
        this.locked = locked;
        this.role = Objects.requireNonNull(role);
        this.mfaSecret = Objects.requireNonNull(mfaSecret);
    }

    public String getUsername() { return username; }
    public String getSalt() { return salt; }
    public String getPasswordHash() { return passwordHash; }
    public Role getRole() { return role; }
    public boolean isLocked() { return locked; }
    public boolean hasMfa() { return !"-".equals(mfaSecret); }
    public String getMfaSecret() { return mfaSecret; }

    void setRole(Role role) { this.role = Objects.requireNonNull(role); }
    void setMfaSecret(String secret) { this.mfaSecret = Objects.requireNonNull(secret); }

    public void recordFailure(int maxAttempts) {
        failedAttempts++;
        if (failedAttempts >= maxAttempts) locked = true;
    }

    public void resetFailures() { failedAttempts = 0; }

    public void unlock() { locked = false; failedAttempts = 0; }

    public String toFileLine() {
        return username + "|" + salt + "|" + passwordHash + "|" + failedAttempts + "|" + locked + "|" + role + "|" + mfaSecret;
    }

    public static User fromFileLine(String line) {
        String[] p = line.split("\\|");
        if (p.length != 7) throw new IllegalArgumentException("Corrupt user record");
        return new User(p[0], p[1], p[2], Integer.parseInt(p[3]), Boolean.parseBoolean(p[4]), Role.valueOf(p[5]), p[6]);
    }
}
