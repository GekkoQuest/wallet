package quest.gekko.wallet.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.config.properties.ApplicationProperties;
import quest.gekko.wallet.entity.User;
import quest.gekko.wallet.util.SecurityUtil;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionManagementService {
    private static final String SESSION_EMAIL_KEY = "email";
    private static final String SESSION_USER_ID_KEY = "userId";
    private static final String SESSION_LOGIN_TIME_KEY = "loginTime";
    private static final String SESSION_CREATED_KEY = "sessionCreated";

    private final ApplicationProperties applicationProperties;

    public void setupUserSession(final HttpSession session, final User user) {
        try {
            log.debug("Setting up session for user: {} on session: {}", SecurityUtil.maskEmail(user.getEmail()), session.getId());

            clearSessionAttributes(session);

            session.setAttribute(SESSION_EMAIL_KEY, user.getEmail());
            session.setAttribute(SESSION_USER_ID_KEY, user.getId());
            session.setAttribute(SESSION_LOGIN_TIME_KEY, System.currentTimeMillis());
            session.setAttribute(SESSION_CREATED_KEY, true);

            final int timeoutSeconds = applicationProperties.getSecurity().getSession().getMaxAgeHours() * 60 * 60;
            session.setMaxInactiveInterval(timeoutSeconds);

            log.info("Session created successfully - ID: {}, Email: {}, UserId: {}",
                    session.getId(),
                    SecurityUtil.maskEmail(user.getEmail()),
                    user.getId());
        } catch (final IllegalStateException e) {
            log.error("Session already invalidated, cannot set attributes: {}", e.getMessage());
            throw new RuntimeException("Session management error - please try logging in again", e);
        } catch (final Exception e) {
            log.error("Unexpected error during session setup: {}", e.getMessage(), e);
            throw new RuntimeException("Session setup failed - please try again", e);
        }
    }

    public String validateSessionAndGetEmail(final HttpSession session) {
        try {
            final String email = getUserEmail(session);
            final Long loginTime = getLoginTime(session);
            final Boolean sessionCreated = (Boolean) session.getAttribute(SESSION_CREATED_KEY);

            log.debug("Session validation - email: {}, loginTime: {}, sessionCreated: {}",
                    email != null ? SecurityUtil.maskEmail(email) : "null",
                    loginTime != null ? "present" : "null",
                    sessionCreated);

            if (email == null || sessionCreated == null || !sessionCreated) {
                log.debug("Session validation failed - missing required attributes");
                return null;
            }

            if (loginTime != null && isSessionExpired(loginTime)) {
                log.warn("Session expired for user: {}", SecurityUtil.maskEmail(email));
                invalidateSession(session);
                return null;
            }

            return email;
        } catch (final IllegalStateException e) {
            log.debug("Session invalid during validation: {}", e.getMessage());
            return null;
        } catch (final Exception e) {
            log.warn("Error during session validation: {}", e.getMessage());
            return null;
        }
    }

    public boolean setupAuthenticatedSession(final HttpSession session, final User user, final HttpServletRequest request, final HttpServletResponse response) {
        try {
            final String securityContext = SecurityUtil.createSecurityContext(request);
            log.info("Setting up authenticated session: {}", securityContext);

            setupUserSession(session, user);

            final String verifyEmail = validateSessionAndGetEmail(session);
            if (verifyEmail == null || !verifyEmail.equals(user.getEmail())) {
                log.error("Session verification failed after creation for user: {}",
                        SecurityUtil.maskEmail(user.getEmail()));
                return false;
            }

            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setDateHeader("Expires", 0);

            log.info("Authenticated session setup successful for user: {}", SecurityUtil.maskEmail(user.getEmail()));
            return true;
        } catch (final Exception e) {
            log.error("Failed to setup authenticated session for user: {}", SecurityUtil.maskEmail(user.getEmail()), e);
            return false;
        }
    }

    public boolean isUserAuthenticated(final HttpSession session) {
        try {
            return validateSessionAndGetEmail(session) != null;
        } catch (final Exception e) {
            log.debug("Authentication check failed: {}", e.getMessage());
            return false;
        }
    }

    public String getUserEmail(final HttpSession session) {
        try {
            return (String) session.getAttribute(SESSION_EMAIL_KEY);
        } catch (final IllegalStateException e) {
            log.debug("Session invalid when retrieving email: {}", e.getMessage());
            return null;
        }
    }

    public String getUserId(final HttpSession session) {
        try {
            return (String) session.getAttribute(SESSION_USER_ID_KEY);
        } catch (final IllegalStateException e) {
            log.debug("Session invalid when retrieving user ID: {}", e.getMessage());
            return null;
        }
    }

    public Long getLoginTime(final HttpSession session) {
        try {
            return (Long) session.getAttribute(SESSION_LOGIN_TIME_KEY);
        } catch (final IllegalStateException e) {
            log.debug("Session invalid when retrieving login time: {}", e.getMessage());
            return null;
        }
    }

    public void invalidateSession(final HttpSession session) {
        try {
            final String email = getUserEmail(session);
            session.invalidate();
            if (email != null) {
                log.info("Session invalidated for user: {}", SecurityUtil.maskEmail(email));
            }
        } catch (final IllegalStateException e) {
            log.debug("Session already invalidated: {}", e.getMessage());
        } catch (final Exception e) {
            log.warn("Session invalidation failed: {}", e.getMessage());
        }
    }

    public void updateSessionActivity(final HttpSession session) {
        try {
            if (isUserAuthenticated(session)) {
                session.setAttribute(SESSION_LOGIN_TIME_KEY, System.currentTimeMillis());
            }
        } catch (final IllegalStateException e) {
            log.debug("Cannot update session activity - session invalid: {}", e.getMessage());
        }
    }

    public long getRemainingSessionTimeMinutes(final HttpSession session) {
        final Long loginTime = getLoginTime(session);

        if (loginTime == null) {
            return 0;
        }

        final long sessionAgeMillis = System.currentTimeMillis() - loginTime;
        final long maxSessionAgeMillis = (long) applicationProperties.getSecurity().getSession().getMaxAgeHours() * 60 * 60 * 1000;
        final long remainingMillis = maxSessionAgeMillis - sessionAgeMillis;

        return Math.max(0, remainingMillis / (60 * 1000));
    }

    private void clearSessionAttributes(final HttpSession session) {
        try {
            session.removeAttribute(SESSION_EMAIL_KEY);
            session.removeAttribute(SESSION_USER_ID_KEY);
            session.removeAttribute(SESSION_LOGIN_TIME_KEY);
            session.removeAttribute(SESSION_CREATED_KEY);
        } catch (final Exception e) {
            log.warn("Failed to clear session attributes: {}", e.getMessage());
        }
    }

    private boolean isSessionExpired(final Long loginTime) {
        if (loginTime == null) {
            return true;
        }

        final long sessionAge = System.currentTimeMillis() - loginTime;
        final long maxSessionAge = (long) applicationProperties.getSecurity().getSession().getMaxAgeHours() * 60 * 60 * 1000;

        return sessionAge > maxSessionAge;
    }
}
