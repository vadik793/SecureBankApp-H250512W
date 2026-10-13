
import java.math.BigDecimal;
import java.util.regex.Pattern;


public final class InputValidator {
    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9_]{3,20}$");
    private static final Pattern ACCOUNT_NO = Pattern.compile("^ACC\\d{8}$");
    private static final BigDecimal MAX_AMOUNT = new BigDecimal("1000000.00");

    private InputValidator() { }

    public static boolean isValidUsername(String s) { return s != null && USERNAME.matcher(s).matches(); }

    public static boolean isValidAccountNumber(String s) { return s != null && ACCOUNT_NO.matcher(s).matches(); }

    public static boolean isValidAccountType(String s) { return "SAVINGS".equals(s) || "CURRENT".equals(s); }


    public static boolean isStrongPassword(char[] p) {
        if (p == null || p.length < 8 || p.length > 64) return false;
        boolean up = false, low = false, dig = false, spc = false;
        for (char c : p) {
            if (Character.isUpperCase(c)) up = true;
            else if (Character.isLowerCase(c)) low = true;
            else if (Character.isDigit(c)) dig = true;
            else spc = true;
        }
        return up && low && dig && spc;
    }


    public static boolean isValidAmount(BigDecimal v) {
        return v != null && v.signum() > 0 && v.scale() <= 2 && v.compareTo(MAX_AMOUNT) <= 0;
    }


    public static BigDecimal parseAmount(String s) {
        if (s == null) return null;
        try {
            BigDecimal v = new BigDecimal(s.trim());
            return isValidAmount(v) ? v.setScale(2) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
