package quest.gekko.wallet.security.audit.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SecurityAuditService {

    public void logSecurityEvent(final SecurityEventType eventType, final String userIdentifier, final String details, final String ipAddress) {
        log.info("SECURITY_EVENT: {} | User: {} | IP: {} | Details: {}", eventType, userIdentifier, ipAddress, details);
        // In production, you might want to send this to a security monitoring system
        // or store in a dedicated audit log database
    }

    public void logFailedAuthentication(final String email, final String ipAddress, final String reason) {
        logSecurityEvent(SecurityEventType.FAILED_AUTHENTICATION, email, reason, ipAddress);
    }

    public void logSuccessfulAuthentication(final String email, final String ipAddress) {
        logSecurityEvent(SecurityEventType.SUCCESSFUL_AUTHENTICATION, email, "Login successful", ipAddress);
    }

    public void logPasswordAccess(final String email, final String ipAddress, final String action) {
        logSecurityEvent(SecurityEventType.PASSWORD_ACCESS, email, action, ipAddress);
    }

    public void logSuspiciousActivity(final String identifier, final String ipAddress, final String activity) {
        logSecurityEvent(SecurityEventType.SUSPICIOUS_ACTIVITY, identifier, activity, ipAddress);
    }

    public enum SecurityEventType {
        FAILED_AUTHENTICATION,
        SUCCESSFUL_AUTHENTICATION,
        PASSWORD_ACCESS,
        SUSPICIOUS_ACTIVITY,
        RATE_LIMIT_EXCEEDED,
        SESSION_HIJACK_ATTEMPT
    }
}