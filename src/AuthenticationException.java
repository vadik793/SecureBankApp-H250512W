// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
/** Deliberately vague: does not reveal whether the username exists or the account is locked. */
public final class AuthenticationException extends BankException {
    private static final long serialVersionUID = 1L;
    public AuthenticationException() { super("Invalid credentials, or the account is locked."); }
}
