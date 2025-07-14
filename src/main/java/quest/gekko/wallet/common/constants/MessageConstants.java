package quest.gekko.wallet.common.constants;

public final class MessageConstants {
    // Success messages
    public static final String PASSWORD_SAVED_SUCCESS = "Password saved successfully";
    public static final String PASSWORD_UPDATED_SUCCESS = "Password updated successfully";
    public static final String PASSWORD_DELETED_SUCCESS = "Password deleted successfully";
    public static final String VERIFICATION_CODE_SENT = "Verification code sent successfully";
    public static final String LOGIN_SUCCESS = "Login successful";
    public static final String LOGOUT_SUCCESS = "Logout successful";

    // Error messages
    public static final String INVALID_EMAIL = "Please enter a valid email address";
    public static final String INVALID_VERIFICATION_CODE = "Please enter a valid 6-digit verification code";
    public static final String RATE_LIMIT_EXCEEDED = "Too many requests. Please wait before trying again.";
    public static final String VERIFICATION_FAILED = "Verification failed. Please try again or request a new code.";
    public static final String SESSION_EXPIRED = "Your session has expired. Please log in again.";
    public static final String UNAUTHORIZED_ACCESS = "Unauthorized access";
    public static final String VAULT_LIMIT_REACHED = "Maximum number of passwords reached for this account";
    public static final String UNEXPECTED_ERROR = "An unexpected error occurred. Please try again.";
    public static final String MASTER_PASSWORD_FAILED = "Incorrect master password. Please try again.";
    public static final String ACCOUNT_LOCKED = "Account is temporarily locked due to multiple failed attempts. Please wait or contact support.";
    public static final String TOO_MANY_UNLOCK_ATTEMPTS = "Too many failed unlock attempts. Please wait before trying again.";

    // Validation messages
    public static final String EMAIL_REQUIRED = "Email is required";
    public static final String CODE_REQUIRED = "Verification code is required";
    public static final String SERVICE_NAME_REQUIRED = "Service name is required";
    public static final String PASSWORD_DATA_REQUIRED = "Password data is required";
    public static final String INVALID_SERVICE_NAME = "Invalid service name format";
    public static final String SERVICE_NAME_TOO_LONG = "Service name is too long";
    public static final String USERNAME_TOO_LONG = "Username is too long";
    public static final String INVALID_USERNAME = "Invalid username format";

    // Security messages
    public static final String SUSPICIOUS_ACTIVITY_DETECTED = "Suspicious activity detected on your account";
    public static final String FAILED_LOGIN_ATTEMPTS = "Multiple failed login attempts detected";
    public static final String UNAUTHORIZED_ACCESS_ATTEMPT = "Unauthorized access attempt detected";
    public static final String VAULT_SECURITY_BREACH_ATTEMPT = "Potential security breach attempt on your vault";

    private MessageConstants() {}
}