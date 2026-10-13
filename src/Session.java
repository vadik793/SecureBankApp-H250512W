
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;


public final class Session {
    private final String username;
    private final Role role;
    private final Duration timeout;
    private Instant lastActivity;

    public Session(String username, Role role, Duration timeout) {
        this.username = Objects.requireNonNull(username);
        this.role = Objects.requireNonNull(role);
        this.timeout = Objects.requireNonNull(timeout);
        if (timeout.isZero() || timeout.isNegative()) throw new IllegalArgumentException("Timeout must be positive");
        this.lastActivity = Instant.now();
    }

    public String getUsername() { return username; }
    public Role getRole() { return role; }

    public boolean isExpired() { return Instant.now().isAfter(lastActivity.plus(timeout)); }

    public void touch() { lastActivity = Instant.now(); }
}
