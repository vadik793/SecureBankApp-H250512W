// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
public final class UnauthorizedException extends BankException {
    private static final long serialVersionUID = 1L;
    public UnauthorizedException() { super("You are not permitted to perform this action."); }
}
