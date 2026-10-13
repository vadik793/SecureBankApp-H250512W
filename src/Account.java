
import java.math.BigDecimal;
import java.math.RoundingMode;







public abstract class Account {
    private final String accountNumber;
    private final String owner;
    private BigDecimal balance;


    protected Account(String accountNumber, String owner, BigDecimal balance) {
        if (!InputValidator.isValidAccountNumber(accountNumber)) throw new IllegalArgumentException("Invalid account number");
        if (!InputValidator.isValidUsername(owner)) throw new IllegalArgumentException("Invalid owner");
        if (balance == null) throw new IllegalArgumentException("Balance required");
        try {
            this.balance = balance.setScale(2, RoundingMode.UNNECESSARY);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("Invalid balance");
        }
        this.accountNumber = accountNumber;
        this.owner = owner;
    }


    protected abstract BigDecimal minimumAllowedBalance();

    public abstract String getType();

    public final String getAccountNumber() { return accountNumber; }
    public final String getOwner() { return owner; }
    public final BigDecimal getBalance() { return balance; }

    public final void deposit(BigDecimal amount) {
        requirePositive(amount);
        balance = balance.add(amount);
    }

    public final void withdraw(BigDecimal amount) {
        requirePositive(amount);
        if (balance.subtract(amount).compareTo(minimumAllowedBalance()) < 0) {
            throw new InsufficientFundsException();
        }
        balance = balance.subtract(amount);
    }

    private static void requirePositive(BigDecimal amount) {
        if (amount == null || amount.signum() <= 0) throw new InvalidInputException("Amount must be positive.");
    }

    public final AccountInfo toInfo() { return new AccountInfo(accountNumber, getType(), balance); }

    public final String toFileLine() {
        return getType() + "|" + accountNumber + "|" + owner + "|" + balance.toPlainString();
    }


    public static Account create(String type, String number, String owner, BigDecimal balance) {
        switch (type) {
            case "SAVINGS": return new SavingsAccount(number, owner, balance);
            case "CURRENT": return new CurrentAccount(number, owner, balance);
            default: throw new IllegalArgumentException("Unknown account type");
        }
    }

    public static Account fromFileLine(String line) {
        String[] p = line.split("\\|");
        if (p.length != 4) throw new IllegalArgumentException("Corrupt account record");
        return create(p[0], p[1], p[2], new BigDecimal(p[3]));
    }
}
