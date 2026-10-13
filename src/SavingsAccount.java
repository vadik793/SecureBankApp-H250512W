// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.math.BigDecimal;

/** Savings account: the balance can never go below zero. */
public final class SavingsAccount extends Account {
    public SavingsAccount(String number, String owner, BigDecimal balance) { super(number, owner, balance); }

    @Override
    protected BigDecimal minimumAllowedBalance() { return BigDecimal.ZERO; }

    @Override
    public String getType() { return "SAVINGS"; }
}
