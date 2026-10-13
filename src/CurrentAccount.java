
import java.math.BigDecimal;


public final class CurrentAccount extends Account {
    private static final BigDecimal OVERDRAFT_LIMIT = new BigDecimal("500.00");

    public CurrentAccount(String number, String owner, BigDecimal balance) { super(number, owner, balance); }

    @Override
    protected BigDecimal minimumAllowedBalance() { return OVERDRAFT_LIMIT.negate(); }

    @Override
    public String getType() { return "CURRENT"; }
}
