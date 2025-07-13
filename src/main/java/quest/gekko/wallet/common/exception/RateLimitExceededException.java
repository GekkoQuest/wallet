package quest.gekko.wallet.common.exception;

public class RateLimitExceededException extends RuntimeException {
    public RateLimitExceededException(final String message) {
        super(message);
    }
}
