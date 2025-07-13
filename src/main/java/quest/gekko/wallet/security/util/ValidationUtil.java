package quest.gekko.wallet.security.util;

import lombok.experimental.UtilityClass;
import quest.gekko.wallet.common.constants.SecurityConstants;

import java.util.regex.Pattern;

@UtilityClass
public class ValidationUtil {
    private static final Pattern EMAIL_PATTERN = Pattern.compile(SecurityConstants.EMAIL_PATTERN);
    private static final Pattern VERIFICATION_CODE_PATTERN = Pattern.compile(SecurityConstants.VERIFICATION_CODE_PATTERN);
    private static final Pattern PASSWORD_NAME_PATTERN = Pattern.compile(SecurityConstants.PASSWORD_NAME_PATTERN);
    private static final Pattern BASE64_PATTERN = Pattern.compile(SecurityConstants.BASE64_PATTERN);
    private static final Pattern DANGEROUS_CHARS = Pattern.compile("[<>\"'&\\x00-\\x1f\\x7f-\\x9f]");

    public static boolean isValidEmail(final String email) {
        return email != null &&
                email.length() >= SecurityConstants.MIN_EMAIL_LENGTH &&
                email.length() <= SecurityConstants.MAX_EMAIL_LENGTH &&
                EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    public static boolean isValidVerificationCode(final String code) {
        return code != null && VERIFICATION_CODE_PATTERN.matcher(code.trim()).matches();
    }

    public static boolean isValidPasswordName(final String name) {
        if (name == null) {
            return false;
        }

        final String trimmed = name.trim();
        return !trimmed.isEmpty() &&
                trimmed.length() <= 100 &&
                PASSWORD_NAME_PATTERN.matcher(trimmed).matches() &&
                !containsDangerousCharacters(trimmed);
    }

    public static boolean isValidBase64(final String data) {
        if (data == null) {
            return false;
        }

        final String trimmed = data.trim();
        return !trimmed.isEmpty() &&
                trimmed.length() % 4 == 0 &&
                BASE64_PATTERN.matcher(trimmed).matches();
    }

    public static boolean containsDangerousCharacters(final String input) {
        return input != null && DANGEROUS_CHARS.matcher(input).find();
    }

    public static boolean isWithinLengthLimits(final String input, final int minLength, final int maxLength) {
        if (input == null) {
            return minLength == 0;
        }

        final int length = input.trim().length();
        return length >= minLength && length <= maxLength;
    }

    public static boolean isStrongPassword(final String password) {
        if (password == null || password.length() < SecurityConstants.MIN_PASSWORD_LENGTH) {
            return false;
        }

        // Check for required character types
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[!@#$%^&*(),.?\":{}|<>_+=\\-\\[\\]\\\\;'/~`].*");

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
}