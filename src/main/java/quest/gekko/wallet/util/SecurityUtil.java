package quest.gekko.wallet.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;

@UtilityClass
public class SecurityUtil {

    private static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    private static final String VERIFICATION_CODE_REGEX = "^[0-9]{6}$";

    /**
     * Masks email for logging privacy
     */
    public static String maskEmail(String email) {
        if (email == null || email.length() < 3) {
            return "***";
        }

        int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return "***";
        }

        String username = email.substring(0, atIndex);
        String domain = email.substring(atIndex);

        if (username.length() <= 2) {
            return "*".repeat(username.length()) + domain;
        }

        return username.charAt(0) + "*".repeat(username.length() - 2) + username.charAt(username.length() - 1) + domain;
    }

    /**
     * Extract client IP address from request, considering proxy headers
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (isValidIpHeader(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (isValidIpHeader(xRealIp)) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Validates email format
     */
    public static boolean isValidEmail(String email) {
        return email != null &&
                email.length() >= 5 &&
                email.length() <= 254 &&
                email.matches(EMAIL_REGEX);
    }

    /**
     * Validates verification code format
     */
    public static boolean isValidVerificationCode(String code) {
        return code != null && code.matches(VERIFICATION_CODE_REGEX);
    }

    /**
     * Sanitizes input by trimming and converting to lowercase
     */
    public static String sanitizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    /**
     * Sanitizes verification code by removing non-digits
     */
    public static String sanitizeVerificationCode(String code) {
        return code != null ? code.trim().replaceAll("[^0-9]", "") : null;
    }

    private static boolean isValidIpHeader(String header) {
        return header != null && !header.isEmpty() && !"unknown".equalsIgnoreCase(header);
    }
}