package quest.gekko.wallet.exception;

public class VaultAccessException extends RuntimeException {
    public VaultAccessException(final String message) {
        super(message);
    }

    public VaultAccessException(final String message, final Throwable cause) {
        super(message, cause);
    }
}