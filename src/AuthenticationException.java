

public final class AuthenticationException extends BankException {
    private static final long serialVersionUID = 1L;
    public AuthenticationException() { super("Invalid credentials, or the account is locked."); }
}
