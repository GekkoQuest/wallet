package quest.gekko.wallet.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@UtilityClass
@Slf4j
public class SecurityUtil {
    private static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    private static final String VERIFICATION_CODE_REGEX = "^[0-9]{6}$";

    public static String maskEmail(final String email) {
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

    public static String getClientIpAddress(final HttpServletRequest request) {
        // Priority order for Cloudflare deployment:
        // 1. CF-Connecting-IP (Cloudflare's real client IP)
        // 2. X-Forwarded-For (standard proxy header)
        // 3. X-Real-IP (alternative proxy header)
        // 4. Remote address (fallback)

        final String cfConnectingIp = request.getHeader("CF-Connecting-IP");
        if (isValidIpHeader(cfConnectingIp)) {
            log.debug("Using CF-Connecting-IP: {}", cfConnectingIp);
            return cfConnectingIp.trim();
        }

        final String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (isValidIpHeader(xForwardedFor)) {
            // X-Forwarded-For can contain multiple IPs, take the first (original client)
            String clientIp = xForwardedFor.split(",")[0].trim();
            log.debug("Using X-Forwarded-For (first): {}", clientIp);
            return clientIp;
        }

        final String xRealIp = request.getHeader("X-Real-IP");
        if (isValidIpHeader(xRealIp)) {
            log.debug("Using X-Real-IP: {}", xRealIp);
            return xRealIp.trim();
        }

        final String remoteAddr = request.getRemoteAddr();
        log.debug("Using RemoteAddr: {}", remoteAddr);
        return remoteAddr != null ? remoteAddr : "unknown";
    }

    public static String getClientProtocol(final HttpServletRequest request) {
        // Check Cloudflare visitor protocol first
        final String cfVisitor = request.getHeader("CF-Visitor");
        if (cfVisitor != null && cfVisitor.contains("\"scheme\":\"https\"")) {
            return "https";
        }

        // Check standard forwarded protocol header
        final String xForwardedProto = request.getHeader("X-Forwarded-Proto");
        if ("https".equalsIgnoreCase(xForwardedProto)) {
            return "https";
        }

        // Fallback to request scheme
        return request.getScheme();
    }

    public static boolean isSecureRequest(final HttpServletRequest request) {
        return "https".equals(getClientProtocol(request));
    }

    public static String getUserAgent(final HttpServletRequest request) {
        final String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.trim().isEmpty()) {
            return "unknown";
        }

        // Basic sanitization - remove potential injection characters
        return userAgent.replaceAll("[<>\"'&]", "").trim();
    }

    public static String getClientCountry(final HttpServletRequest request) {
        final String cfCountry = request.getHeader("CF-IPCountry");
        if (cfCountry != null && !cfCountry.trim().isEmpty() && !"XX".equals(cfCountry)) {
            return cfCountry.trim().toUpperCase();
        }
        return "unknown";
    }

    public static boolean isCloudflareRequest(final HttpServletRequest request) {
        return request.getHeader("CF-Ray") != null ||
                request.getHeader("CF-Connecting-IP") != null;
    }

    public static String getCloudflareRayId(final HttpServletRequest request) {
        final String cfRay = request.getHeader("CF-Ray");
        return cfRay != null ? cfRay.trim() : "none";
    }

    public static boolean isValidEmail(final String email) {
        return email != null &&
                email.length() >= 5 &&
                email.length() <= 254 &&
                email.matches(EMAIL_REGEX);
    }

    public static boolean isValidVerificationCode(final String code) {
        return code != null && code.matches(VERIFICATION_CODE_REGEX);
    }

    public static String sanitizeEmail(final String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    public static String sanitizeVerificationCode(final String code) {
        return code != null ? code.trim().replaceAll("[^0-9]", "") : null;
    }

    private static boolean isValidIpHeader(final String header) {
        return header != null &&
                !header.trim().isEmpty() &&
                !"unknown".equalsIgnoreCase(header.trim()) &&
                !"null".equalsIgnoreCase(header.trim());
    }

    public static String createSecurityContext(final HttpServletRequest request) {
        return String.format("IP: %s, Protocol: %s, Country: %s, CF-Ray: %s, UserAgent: %s",
                getClientIpAddress(request),
                getClientProtocol(request),
                getClientCountry(request),
                getCloudflareRayId(request),
                getUserAgent(request).substring(0, Math.min(50, getUserAgent(request).length()))
        );
    }
}