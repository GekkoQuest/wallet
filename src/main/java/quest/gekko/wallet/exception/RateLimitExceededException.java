package quest.gekko.wallet.exception;

public class RateLimitExceededException extends RuntimeException {
    public RateLimitExceededException(final String message) {
        super(message);
    }
}
