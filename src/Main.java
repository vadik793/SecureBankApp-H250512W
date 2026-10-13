
import java.io.Console;
import java.math.BigDecimal;
import java.util.List;
import java.util.Scanner;


public class Main {
    private static final Scanner IN = new Scanner(System.in);
    private static final Console CONSOLE = System.console();
    private static Bank bank;

    public static void main(String[] args) {
        try {
            bank = new Bank(new FileStorage("data"));
        } catch (RuntimeException e) {
            System.out.println("Unable to start: data storage is unavailable.");
            return;
        }
        System.out.println("=== Secure Banking Application ===");
        while (true) {
            System.out.println("\n1. Login\n2. Register\n3. Exit");
            try {
                switch (ask("Choose: ")) {
                    case "1": doLogin(); break;
                    case "2": doRegister(); break;
                    case "3": System.out.println("Goodbye."); return;
                    default: System.out.println("Invalid choice.");
                }
            } catch (BankException e) {
                System.out.println(e.getMessage());
            } catch (RuntimeException e) {
                System.out.println("An unexpected error occurred.");
                bank.logUnexpected("-", e);
            }
        }
    }


    private static String ask(String prompt) {
        System.out.print(prompt);
        if (!IN.hasNextLine()) { System.out.println(); System.exit(0); }
        return IN.nextLine().trim();
    }


    private static char[] askPassword(String prompt) {
        if (CONSOLE != null) return CONSOLE.readPassword(prompt);
        System.out.print(prompt);
        if (!IN.hasNextLine()) { System.out.println(); System.exit(0); }
        return IN.nextLine().toCharArray();
    }

    private static BigDecimal askAmount() {
        BigDecimal amt = InputValidator.parseAmount(ask("Amount: "));
        if (amt == null) throw new InvalidInputException("Invalid amount (positive, max 2 decimals, up to 1,000,000).");
        return amt;
    }


    private static void doRegister() {
        String user = ask("Choose username: ");
        char[] pw = askPassword("Choose password: ");
        try {
            Role role = bank.register(user, pw);
            System.out.println("Registration successful.");
            if (role == Role.ADMIN) {
                System.out.println("You are the first user, so you were made the ADMINISTRATOR.");
                System.out.println("Register a second user to use customer banking features.");
            }
        } finally {
            java.util.Arrays.fill(pw, ' ');
        }
    }

    private static void doLogin() {
        String user = ask("Username: ");
        char[] pw = askPassword("Password: ");
        Session s;
        try {
            s = bank.login(user, pw, () -> ask("Verification code (6 digits): "));
        } finally {
            java.util.Arrays.fill(pw, ' ');
        }
        System.out.println("Welcome, " + s.getUsername() + "!");
        switch (s.getRole()) {
            case ADMIN: adminMenu(s); break;
            case AUDITOR: auditorMenu(s); break;
            default: customerMenu(s);
        }
    }

    private static void showMfaSetup(Session s) {
        String secret = bank.enableMfa(s);
        System.out.println("Two-factor authentication enabled.");
        System.out.println("Add this to your authenticator app (time-based, 6 digits). It is shown only once:");
        System.out.println("  Secret : " + secret);
        System.out.println("  Or URI : otpauth://totp/SecureBank:" + s.getUsername() + "?secret=" + secret + "&issuer=SecureBank");
    }


    private static boolean handle(RuntimeException e, Session s) {
        if (e instanceof SessionExpiredException) {
            System.out.println(e.getMessage());
            return true;
        }
        if (e instanceof BankException) {
            System.out.println(e.getMessage());
        } else {
            System.out.println("An unexpected error occurred.");
            bank.logUnexpected(s.getUsername(), e);
        }
        return false;
    }


    private static void customerMenu(Session s) {
        while (true) {
            System.out.println("\n--- Customer Menu (" + s.getUsername() + ") ---");
            System.out.println("1. Create new account\n2. View balances\n3. Deposit\n4. Withdraw\n5. Transaction history\n6. Enable two-factor authentication\n7. Logout");
            String choice = ask("Choose: ");
            try {
                bank.checkSession(s);
                switch (choice) {
                    case "1": {
                        AccountInfo a = bank.createAccount(s, ask("Account type (SAVINGS or CURRENT): ").toUpperCase());
                        System.out.println("Account created: " + a.number() + " [" + a.type() + "]");
                        break;
                    }
                    case "2": showBalances(s); break;
                    case "3": {
                        String no = ask("Account number: ");
                        System.out.println("Success. New balance: " + bank.deposit(s, no, askAmount()).toPlainString());
                        break;
                    }
                    case "4": {
                        String no = ask("Account number: ");
                        System.out.println("Success. New balance: " + bank.withdraw(s, no, askAmount()).toPlainString());
                        break;
                    }
                    case "5": {
                        List<String> h = bank.history(s, ask("Account number: "));
                        if (h.isEmpty()) System.out.println("No transactions yet.");
                        for (String line : h) System.out.println(line);
                        break;
                    }
                    case "6": showMfaSetup(s); break;
                    case "7": bank.logout(s); System.out.println("Logged out."); return;
                    default: System.out.println("Invalid choice.");
                }
            } catch (RuntimeException e) {
                if (handle(e, s)) return;
            }
        }
    }

    private static void showBalances(Session s) {
        List<AccountInfo> list = bank.getAccounts(s);
        if (list.isEmpty()) { System.out.println("You have no accounts yet."); return; }
        for (AccountInfo a : list)
            System.out.println(a.number() + "  [" + a.type() + "]  balance: " + a.balance().toPlainString());
    }


    private static void adminMenu(Session s) {
        while (true) {
            System.out.println("\n--- Administrator Menu (" + s.getUsername() + ") ---");
            System.out.println("1. List users\n2. Unlock a user\n3. Assign role (CUSTOMER / AUDITOR)\n4. View audit log\n5. Verify audit log integrity\n6. Enable two-factor authentication\n7. Logout");
            String choice = ask("Choose: ");
            try {
                bank.checkSession(s);
                switch (choice) {
                    case "1": for (String u : bank.listUsers(s)) System.out.println(u); break;
                    case "2": bank.unlockUser(s, ask("Username to unlock: ")); System.out.println("User unlocked."); break;
                    case "3": {
                        String who = ask("Username: ");
                        bank.assignRole(s, who, ask("New role (CUSTOMER or AUDITOR): ").toUpperCase());
                        System.out.println("Role updated.");
                        break;
                    }
                    case "4": for (String l : bank.readAuditLog(s)) System.out.println(l); break;
                    case "5": System.out.println(bank.verifyAuditLog(s)); break;
                    case "6": showMfaSetup(s); break;
                    case "7": bank.logout(s); System.out.println("Logged out."); return;
                    default: System.out.println("Invalid choice.");
                }
            } catch (RuntimeException e) {
                if (handle(e, s)) return;
            }
        }
    }


    private static void auditorMenu(Session s) {
        while (true) {
            System.out.println("\n--- Auditor Menu (" + s.getUsername() + ") ---");
            System.out.println("1. View audit log\n2. Verify audit log integrity\n3. Enable two-factor authentication\n4. Logout");
            String choice = ask("Choose: ");
            try {
                bank.checkSession(s);
                switch (choice) {
                    case "1": for (String l : bank.readAuditLog(s)) System.out.println(l); break;
                    case "2": System.out.println(bank.verifyAuditLog(s)); break;
                    case "3": showMfaSetup(s); break;
                    case "4": bank.logout(s); System.out.println("Logged out."); return;
                    default: System.out.println("Invalid choice.");
                }
            } catch (RuntimeException e) {
                if (handle(e, s)) return;
            }
        }
    }
}
