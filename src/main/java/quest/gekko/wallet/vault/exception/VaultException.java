package quest.gekko.wallet.vault.exception;

import lombok.Getter;

@Getter
public class VaultException extends RuntimeException {
  private final VaultErrorType errorType;

  public VaultException(final VaultErrorType errorType, final String message) {
    super(message);
    this.errorType = errorType;
  }

  public VaultException(final VaultErrorType errorType, final String message, final Throwable cause) {
    super(message, cause);
    this.errorType = errorType;
  }

    public enum VaultErrorType {
    LIMIT_EXCEEDED,
    UNAUTHORIZED_ACCESS,
    DATA_CORRUPTION,
    ENCRYPTION_ERROR,
    VALIDATION_ERROR,
    STORAGE_ERROR
  }
}