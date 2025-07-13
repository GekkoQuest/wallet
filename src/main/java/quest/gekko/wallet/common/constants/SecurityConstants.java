package quest.gekko.wallet.common.constants;

public final class SecurityConstants {
    // Session keys
    public static final String SESSION_EMAIL_KEY = "email";
    public static final String SESSION_USER_ID_KEY = "userId";
    public static final String SESSION_LOGIN_TIME_KEY = "loginTime";

    // Validation patterns
    public static final String EMAIL_PATTERN = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    public static final String VERIFICATION_CODE_PATTERN = "^[0-9]{6}$";
    public static final String PASSWORD_NAME_PATTERN = "^[a-zA-Z0-9\\s\\-_\\.]{1,100}$";
    public static final String BASE64_PATTERN = "^[A-Za-z0-9+/]*={0,2}$";

    // Security limits
    public static final int MIN_PASSWORD_LENGTH = 12;
    public static final int MAX_PASSWORD_LENGTH = 128;
    public static final int VERIFICATION_CODE_LENGTH = 6;
    public static final int MAX_EMAIL_LENGTH = 320;
    public static final int MIN_EMAIL_LENGTH = 5;

    // Rate limiting
    public static final int DEFAULT_EMAIL_SEND_LIMIT_PER_HOUR = 10;
    public static final int DEFAULT_EMAIL_SEND_LIMIT_PER_MINUTE = 3;
    public static final int DEFAULT_CODE_VERIFY_LIMIT_PER_HOUR = 20;
    public static final int DEFAULT_CODE_VERIFY_LIMIT_PER_MINUTE = 5;

    // Session timeouts
    public static final int DEFAULT_SESSION_TIMEOUT_HOURS = 24;
    public static final int DEFAULT_INACTIVE_SESSION_TIMEOUT_MINUTES = 30;

    // Encryption
    public static final int PBKDF2_ITERATIONS = 100000;
    public static final int AES_KEY_LENGTH = 256;
    public static final int AES_IV_LENGTH = 12;
    public static final int SALT_LENGTH = 16;

    private SecurityConstants() {}
}