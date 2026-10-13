

public final class AccountNotFoundException extends BankException {
    private static final long serialVersionUID = 1L;
    public AccountNotFoundException() { super("Account not found."); }
}
