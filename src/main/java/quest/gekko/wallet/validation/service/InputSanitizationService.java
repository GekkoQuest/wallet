package quest.gekko.wallet.validation.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.security.util.ValidationUtil;

import java.util.regex.Pattern;

@Service
@Slf4j
public class InputSanitizationService {
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern VERIFICATION_CODE_PATTERN = Pattern.compile("^[0-9]{6}$");
    private static final Pattern SERVICE_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s\\-_\\.]{1,100}$");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s\\-_\\.@]{1,200}$");
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

    // Characters that could be used for XSS or injection attacks
    private static final Pattern DANGEROUS_CHARS = Pattern.compile("[<>\"'&\\x00-\\x1f\\x7f-\\x9f]");

    public boolean isValidEmail(final String email) {
        if (email == null) {
            return false;
        }

        final String trimmed = email.trim();
        return trimmed.length() >= 5 &&
                trimmed.length() <= 320 &&
                EMAIL_PATTERN.matcher(trimmed).matches();
    }

    public boolean isValidVerificationCode(final String code) {
        if (code == null) {
            return false;
        }

        return VERIFICATION_CODE_PATTERN.matcher(code.trim()).matches();
    }

    public boolean isValidPasswordName(final String name) {
        if (name == null) {
            return false;
        }

        final String trimmed = name.trim();
        return !trimmed.isEmpty() &&
                trimmed.length() <= 100 &&
                SERVICE_NAME_PATTERN.matcher(trimmed).matches() &&
                !containsDangerousCharacters(trimmed);
    }

    public boolean isValidUsername(final String username) {
        if (username == null || username.trim().isEmpty()) {
            return true; // Username is optional
        }

        final String trimmed = username.trim();
        return trimmed.length() <= 200 &&
                USERNAME_PATTERN.matcher(trimmed).matches() &&
                !containsDangerousCharacters(trimmed);
    }

    public boolean isValidBase64(final String data) {
        if (data == null) {
            return false;
        }

        final String trimmed = data.trim();
        return !trimmed.isEmpty() &&
                trimmed.length() % 4 == 0 &&
                BASE64_PATTERN.matcher(trimmed).matches();
    }

    public String sanitizeEmail(final String email) {
        if (email == null) {
            return null;
        }

        final String sanitized = email.trim().toLowerCase();

        if (!isValidEmail(sanitized)) {
            log.warn("Email failed validation after sanitization: {}", maskEmail(sanitized));
            return null;
        }

        return sanitized;
    }

    public String sanitizePasswordName(final String name) {
        if (name == null) {
            return null;
        }

        String sanitized = name.trim();

        // Remove dangerous characters
        sanitized = DANGEROUS_CHARS.matcher(sanitized).replaceAll("");

        // Trim again after character removal
        sanitized = sanitized.trim();

        if (sanitized.isEmpty() || sanitized.length() > 100) {
            log.warn("Service name failed validation after sanitization");
            return null;
        }

        return sanitized;
    }

    public String sanitizeUsername(final String username) {
        if (username == null || username.trim().isEmpty()) {
            return null; // Return null for empty usernames (they're optional)
        }

        String sanitized = username.trim();

        // Remove dangerous characters
        sanitized = DANGEROUS_CHARS.matcher(sanitized).replaceAll("");

        // Trim again after character removal
        sanitized = sanitized.trim();

        if (sanitized.isEmpty()) {
            return null; // Return null if empty after sanitization
        }

        if (sanitized.length() > 200) {
            log.warn("Username too long after sanitization: {} characters", sanitized.length());
            return null;
        }

        return sanitized;
    }

    public String sanitizeVerificationCode(final String code) {
        if (code == null) {
            return null;
        }

        // Remove everything except digits
        final String sanitized = code.replaceAll("[^0-9]", "");

        if (sanitized.length() != 6) {
            log.warn("Verification code has invalid length after sanitization: {}", sanitized.length());
            return null;
        }

        return sanitized;
    }

    public String sanitizeBase64(final String data) {
        if (data == null) {
            return null;
        }

        final String sanitized = data.trim();

        if (!isValidBase64(sanitized)) {
            log.warn("Base64 data failed validation after sanitization");
            return null;
        }

        return sanitized;
    }

    /**
     * Generic way to sanitize string input by removing dangerous characters
     */
    public String sanitizeString(String input, int maxLength) {
        if (input == null) {
            return null;
        }

        String sanitized = input.trim();

        // Remove dangerous characters
        sanitized = DANGEROUS_CHARS.matcher(sanitized).replaceAll("");

        if (sanitized.length() > maxLength) {
            sanitized = sanitized.substring(0, maxLength);
        }

        return sanitized.trim();
    }

    public boolean containsDangerousCharacters(final String input) {
        if (input == null) {
            return false;
        }

        return DANGEROUS_CHARS.matcher(input).find();
    }

    public boolean isWithinLengthLimits(final String input, final int minLength, final int maxLength) {
        return ValidationUtil.isWithinLengthLimits(input, minLength, maxLength);
    }

    public boolean isPasswordNameValid(final String name) {
        return name != null &&
                isWithinLengthLimits(name, 1, 100) &&
                !containsDangerousCharacters(name) &&
                SERVICE_NAME_PATTERN.matcher(name.trim()).matches();
    }

    public boolean isUsernameValid(final String username) {
        if (username == null || username.trim().isEmpty()) {
            return true; // Username is optional
        }

        return isWithinLengthLimits(username, 1, 200) &&
                !containsDangerousCharacters(username) &&
                USERNAME_PATTERN.matcher(username.trim()).matches();
    }

    private String maskEmail(final String email) {
        if (email == null || email.length() < 3) {
            return "***";
        }

        final int atIndex = email.indexOf('@');

        if (atIndex <= 0) {
            return "***";
        }

        final String username = email.substring(0, atIndex);
        final String domain = email.substring(atIndex);

        if (username.length() <= 2) {
            return "*".repeat(username.length()) + domain;
        }

        return username.charAt(0) + "*".repeat(username.length() - 2) + username.charAt(username.length() - 1) + domain;
    }
}