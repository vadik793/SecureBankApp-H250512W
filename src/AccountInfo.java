// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.math.BigDecimal;

/** Immutable, read-only snapshot of an account. The UI receives this instead of the real Account object. */
public record AccountInfo(String number, String type, BigDecimal balance) { }
