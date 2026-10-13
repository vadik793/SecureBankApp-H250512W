// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.math.BigDecimal;

/** Current account: allows a fixed overdraft of 500.00 (polymorphism: same withdraw(), different rule). */
public final class CurrentAccount extends Account {
    private static final BigDecimal OVERDRAFT_LIMIT = new BigDecimal("500.00");

    public CurrentAccount(String number, String owner, BigDecimal balance) { super(number, owner, balance); }

    @Override
    protected BigDecimal minimumAllowedBalance() { return OVERDRAFT_LIMIT.negate(); }

    @Override
    public String getType() { return "CURRENT"; }
}
