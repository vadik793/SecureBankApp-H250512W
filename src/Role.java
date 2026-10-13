
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;








public enum Role {
    CUSTOMER(EnumSet.of(Permission.CREATE_ACCOUNT, Permission.VIEW_BALANCE, Permission.DEPOSIT,
            Permission.WITHDRAW, Permission.VIEW_HISTORY, Permission.ENABLE_MFA)),
    AUDITOR(EnumSet.of(Permission.VIEW_AUDIT_LOG, Permission.VERIFY_AUDIT_LOG, Permission.ENABLE_MFA)),
    ADMIN(EnumSet.of(Permission.MANAGE_USERS, Permission.ASSIGN_ROLES, Permission.VIEW_AUDIT_LOG,
            Permission.VERIFY_AUDIT_LOG, Permission.ENABLE_MFA));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {

        this.permissions = Collections.unmodifiableSet(EnumSet.copyOf(permissions));
    }

    public boolean can(Permission p) { return permissions.contains(p); }

    public Set<Permission> getPermissions() { return permissions; }
}
