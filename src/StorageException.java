// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
/** Raised when data cannot be read or saved. The message is generic; no file paths or system details. */
public final class StorageException extends BankException {
    private static final long serialVersionUID = 1L;

    public StorageException() { super("Storage error. The operation could not be completed."); }
}
