// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Immutable object (Unit 2): final class, private final fields, no setters, and only immutable field types.
 * Once created it can never be altered, so it is safe to share.
 */
public final class Transaction {
    public enum Type { DEPOSIT, WITHDRAW }

    private final String accountNumber;
    private final Type type;
    private final BigDecimal amount;
    private final BigDecimal balanceAfter;
    private final LocalDateTime time;

    public Transaction(String accountNumber, Type type, BigDecimal amount, BigDecimal balanceAfter, LocalDateTime time) {
        if (!InputValidator.isValidAccountNumber(accountNumber)) throw new IllegalArgumentException("Invalid account number");
        this.accountNumber = accountNumber;
        this.type = java.util.Objects.requireNonNull(type);
        this.amount = java.util.Objects.requireNonNull(amount);
        this.balanceAfter = java.util.Objects.requireNonNull(balanceAfter);
        this.time = java.util.Objects.requireNonNull(time);
    }

    public String getAccountNumber() { return accountNumber; }

    public String toFileLine() {
        return accountNumber + "|" + type + "|" + amount.toPlainString() + "|" + balanceAfter.toPlainString() + "|" + time;
    }

    public static Transaction fromFileLine(String line) {
        String[] p = line.split("\\|");
        if (p.length != 5) throw new IllegalArgumentException("Corrupt transaction record");
        return new Transaction(p[0], Type.valueOf(p[1]), new BigDecimal(p[2]), new BigDecimal(p[3]), LocalDateTime.parse(p[4]));
    }

    @Override
    public String toString() {
        return String.format("%s | %-8s | %12s | balance: %12s", time.withNano(0), type, amount.toPlainString(), balanceAfter.toPlainString());
    }
}
