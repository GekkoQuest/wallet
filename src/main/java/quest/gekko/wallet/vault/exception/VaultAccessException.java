package quest.gekko.wallet.vault.exception;

public class VaultAccessException extends RuntimeException {
    public VaultAccessException(final String message) {
        super(message);
    }

    public VaultAccessException(final String message, final Throwable cause) {
        super(message, cause);
    }
}