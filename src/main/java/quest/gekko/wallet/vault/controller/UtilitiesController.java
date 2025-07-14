package quest.gekko.wallet.vault.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import quest.gekko.wallet.vault.service.AccountDeletionService;
import quest.gekko.wallet.audit.service.SecurityAuditService;
import quest.gekko.wallet.security.session.service.SessionManagementService;
import quest.gekko.wallet.security.util.SecurityUtil;

@Controller
@RequestMapping("/vault")
@RequiredArgsConstructor
@Slf4j
public class UtilitiesController {
    private static final String UTILITIES_VIEW = "vault/utilities";
    private static final String LOGIN_REDIRECT = "redirect:/";
    private static final String DASHBOARD_REDIRECT = "redirect:/vault/dashboard";

    private final AccountDeletionService accountDeletionService;
    private final SecurityAuditService securityAuditService;
    private final SessionManagementService sessionManagementService;

    @GetMapping("/utilities")
    public String showUtilities(final HttpSession session, final HttpServletRequest request, final Model model) {
        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            log.warn("No valid session for utilities access");
            return LOGIN_REDIRECT;
        }

        try {
            final String clientIp = SecurityUtil.getClientIpAddress(request);

            model.addAttribute("email", SecurityUtil.maskEmail(email));
            model.addAttribute("remainingSessionTime", sessionManagementService.getRemainingSessionTimeMinutes(session));

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Utilities page accessed",
                    clientIp
            );

            sessionManagementService.updateSessionActivity(session);
            log.info("Utilities page accessed by user: {}", SecurityUtil.maskEmail(email));

            return UTILITIES_VIEW;
        } catch (final Exception e) {
            log.error("Error loading utilities page for user: {}", SecurityUtil.maskEmail(email), e);
            model.addAttribute("error", "Unable to load utilities page");
            return DASHBOARD_REDIRECT;
        }
    }

    @PostMapping("/delete-account")
    public String deleteAccount(
            @RequestParam("confirmationText") final String confirmationText,
            final HttpSession session,
            final HttpServletRequest httpRequest,
            final RedirectAttributes redirectAttributes) {

        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            return LOGIN_REDIRECT;
        }

        final String clientIp = SecurityUtil.getClientIpAddress(httpRequest);

        if (!"DELETE".equals(confirmationText)) {
            redirectAttributes.addFlashAttribute("error", "Please type 'DELETE' to confirm account deletion");
            return "redirect:/vault/utilities";
        }

        try {
            log.warn("Account deletion request from user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp);

            final boolean deleted = accountDeletionService.deleteAccount(email, clientIp);

            if (deleted) {
                securityAuditService.logSecurityEvent(
                        SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                        email,
                        "Account successfully deleted",
                        clientIp
                );

                sessionManagementService.invalidateSession(session);

                log.warn("Account deleted successfully for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp);

                redirectAttributes.addFlashAttribute("success",
                        "Your account has been permanently deleted. Thank you for using our demo service.");
                return LOGIN_REDIRECT;

            } else {
                securityAuditService.logSecurityEvent(
                        SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                        email,
                        "Failed account deletion attempt - unexpected failure",
                        clientIp
                );

                redirectAttributes.addFlashAttribute("error",
                        "Account deletion failed. Please try again.");
                return "redirect:/vault/utilities";
            }

        } catch (final SecurityException e) {
            log.warn("Security violation during account deletion for user: {} from IP: {}: {}",
                    SecurityUtil.maskEmail(email), clientIp, e.getMessage());

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Security violation during account deletion: " + e.getMessage(),
                    clientIp
            );

            redirectAttributes.addFlashAttribute("error", "Security validation failed");
            return "redirect:/vault/utilities";

        } catch (final Exception e) {
            log.error("Unexpected error during account deletion for user: {} from IP: {}",
                    SecurityUtil.maskEmail(email), clientIp, e);

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unexpected error during account deletion",
                    clientIp
            );

            redirectAttributes.addFlashAttribute("error", "An unexpected error occurred. Please try again.");
            return "redirect:/vault/utilities";
        }
    }
}