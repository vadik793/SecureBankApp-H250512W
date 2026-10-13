// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Multi-Factor Authentication (possession factor): time-based one-time passwords, RFC 6238
 * (HMAC-SHA1, 6 digits, 30 second steps). Compatible with Google Authenticator, Microsoft Authenticator, etc.
 */
public final class Totp {
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() { }

    public static byte[] newSecret() {
        byte[] b = new byte[20];
        RANDOM.nextBytes(b);
        return b;
    }

    public static String toBase32(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(B32.charAt((buffer << (5 - bits)) & 31));
        return sb.toString();
    }

    public static byte[] fromBase32(String s) {
        byte[] out = new byte[s.length() * 5 / 8];
        int buffer = 0, bits = 0, idx = 0;
        for (char c : s.toCharArray()) {
            int v = B32.indexOf(c);
            if (v < 0) throw new IllegalArgumentException("Invalid Base32");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                out[idx++] = (byte) ((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out;
    }

    public static String codeAt(byte[] secret, long epochSeconds) {
        try {
            byte[] msg = ByteBuffer.allocate(8).putLong(epochSeconds / 30).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] h = mac.doFinal(msg);
            int off = h[h.length - 1] & 0x0f;
            int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("TOTP unavailable");
        }
    }

    /** Accepts the current code and one step either side (clock drift). Input must be exactly 6 digits. */
    public static boolean verify(byte[] secret, String code, long nowSeconds) {
        if (code == null || !code.matches("\\d{6}")) return false;
        boolean ok = false;
        for (int w = -1; w <= 1; w++) {
            ok |= MessageDigest.isEqual(codeAt(secret, nowSeconds + 30L * w).getBytes(), code.getBytes());
        }
        return ok;
    }
}
