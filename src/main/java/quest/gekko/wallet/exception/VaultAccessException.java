package quest.gekko.wallet.exception;

public class VaultAccessException extends RuntimeException {
    public VaultAccessException(String message) {
        super(message);
    }

    public VaultAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}