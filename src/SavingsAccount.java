
import java.math.BigDecimal;


public final class SavingsAccount extends Account {
    public SavingsAccount(String number, String owner, BigDecimal balance) { super(number, owner, balance); }

    @Override
    protected BigDecimal minimumAllowedBalance() { return BigDecimal.ZERO; }

    @Override
    public String getType() { return "SAVINGS"; }
}
