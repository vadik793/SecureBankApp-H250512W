// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Secure logging (Unit: Secure Logging Techniques).
 * - Structured JSON, one event per line, with a timestamp and the user (supports non-repudiation).
 * - Never receives passwords or other secrets; every value is escaped (prevents log injection) and length-limited.
 * - Append-only, and TAMPER-EVIDENT: each entry stores the SHA-256 hash of the previous entry (a hash chain),
 *   so editing or deleting an earlier line is detected by verify().
 */
public final class AuditLogger {
    private static final String FILE = "audit.log";
    private static final String GENESIS = "0".repeat(64);
    private static final String HASH_MARK = ",\"hash\":\"";
    private static final int MAX_FIELD = 200;

    private final DataStore store;
    private String lastHash;

    public AuditLogger(DataStore store) {
        this.store = store;
        List<String> lines = store.readLines(FILE);
        if (lines.isEmpty()) {
            lastHash = GENESIS;
        } else {
            String last = lines.get(lines.size() - 1);
            int i = last.lastIndexOf(HASH_MARK);
            lastHash = (i >= 0 && last.endsWith("\"}")) ? last.substring(i + HASH_MARK.length(), last.length() - 2) : sha256(last);
        }
    }

    public synchronized void log(String event, String user, String detail) {
        String body = "{\"time\":\"" + LocalDateTime.now().withNano(0) + "\""
                + ",\"event\":\"" + esc(event) + "\""
                + ",\"user\":\"" + esc(user) + "\""
                + ",\"detail\":\"" + esc(detail) + "\""
                + ",\"source\":\"console\""
                + ",\"prev\":\"" + lastHash + "\"}";
        String hash = sha256(body);
        store.appendLine(FILE, body.substring(0, body.length() - 1) + HASH_MARK + hash + "\"}");
        lastHash = hash;
    }

    public List<String> readAll() { return store.readLines(FILE); }

    /** Re-computes the hash chain and reports whether the log has been altered. */
    public String verify() {
        String prev = GENESIS;
        int n = 0;
        for (String line : store.readLines(FILE)) {
            n++;
            int i = line.lastIndexOf(HASH_MARK);
            if (i < 0 || !line.endsWith("\"}")) return "TAMPERED: line " + n + " is malformed.";
            String body = line.substring(0, i) + "}";
            String hash = line.substring(i + HASH_MARK.length(), line.length() - 2);
            if (!body.endsWith("\"prev\":\"" + prev + "\"}")) return "TAMPERED: chain broken at line " + n + ".";
            if (!sha256(body).equals(hash)) return "TAMPERED: line " + n + " was modified.";
            prev = hash;
        }
        return "OK: " + n + " entries verified, no tampering detected.";
    }

    private static String esc(String s) {
        if (s == null) return "-";
        if (s.length() > MAX_FIELD) s = s.substring(0, MAX_FIELD);
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                default: sb.append(c < 0x20 ? ' ' : c);
            }
        }
        return sb.toString();
    }

    private static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }
}
