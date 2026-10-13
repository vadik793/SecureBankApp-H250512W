// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
/** Same message whether the account does not exist or belongs to someone else (prevents enumeration). */
public final class AccountNotFoundException extends BankException {
    private static final long serialVersionUID = 1L;
    public AccountNotFoundException() { super("Account not found."); }
}
