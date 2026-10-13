// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
/** Base custom exception. Its message is always safe to show to the user (no internal details). */
public class BankException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public BankException(String message) { super(message); }
}
