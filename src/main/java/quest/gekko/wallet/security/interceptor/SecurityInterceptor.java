package quest.gekko.wallet.security.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import quest.gekko.wallet.security.audit.service.SecurityAuditService;
import quest.gekko.wallet.security.authentication.service.SessionManagementService;
import quest.gekko.wallet.security.util.SecurityUtil;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityInterceptor implements HandlerInterceptor {
    private final SessionManagementService sessionManagementService;
    private final SecurityAuditService securityAuditService;

    @Override
    public boolean preHandle(@NonNull final HttpServletRequest request, @NonNull final HttpServletResponse response, @NonNull final Object handler) throws Exception {
        final String email = sessionManagementService.validateSessionAndGetEmail(request.getSession());

        if (email == null) {
            log.warn("Unauthorized access attempt to {} from IP: {}",
                    request.getRequestURI(), SecurityUtil.getClientIpAddress(request));

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    "anonymous",
                    "Unauthorized access attempt to " + request.getRequestURI(),
                    SecurityUtil.getClientIpAddress(request)
            );

            response.sendRedirect("/");
            return false;
        }

        sessionManagementService.updateSessionActivity(request.getSession());

        request.setAttribute("authenticatedEmail", email);
        request.setAttribute("authenticatedUserId", sessionManagementService.getUserId(request.getSession()));
        return true;
    }
}