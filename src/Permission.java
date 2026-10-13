// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
/** Fine-grained permissions. Code checks for a PERMISSION, never for a specific user name or role name. */
public enum Permission {
    CREATE_ACCOUNT, VIEW_BALANCE, DEPOSIT, WITHDRAW, VIEW_HISTORY,
    ENABLE_MFA,
    MANAGE_USERS, ASSIGN_ROLES,
    VIEW_AUDIT_LOG, VERIFY_AUDIT_LOG
}
