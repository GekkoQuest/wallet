package quest.gekko.wallet.authentication.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import quest.gekko.wallet.authentication.dto.request.SendCodeRequest;
import quest.gekko.wallet.authentication.dto.request.VerifyCodeRequest;
import quest.gekko.wallet.user.entity.User;
import quest.gekko.wallet.authentication.exception.AuthenticationException;
import quest.gekko.wallet.common.exception.RateLimitExceededException;
import quest.gekko.wallet.authentication.service.AuthenticationService;
import quest.gekko.wallet.audit.service.SecurityAuditService;
import quest.gekko.wallet.security.session.service.SessionManagementService;
import quest.gekko.wallet.security.util.SecurityUtil;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {
    private static final String LOGIN_VIEW = "auth/login";
    private static final String VERIFY_VIEW = "auth/verify";
    private static final String DASHBOARD_REDIRECT = "redirect:/vault/dashboard";
    private static final String LOGIN_REDIRECT = "redirect:/";

    private final AuthenticationService authenticationService;
    private final SecurityAuditService securityAuditService;
    private final SessionManagementService sessionManagementService;

    @GetMapping("/")
    public String loginPage(final HttpSession session,
                            final HttpServletRequest request,
                            final Model model,
                            @ModelAttribute(name = "success") String success,
                            @ModelAttribute(name = "error") String error) {
        if (sessionManagementService.isUserAuthenticated(session)) {
            final String email = sessionManagementService.getUserEmail(session);
            log.info("User already authenticated ({}), redirecting to dashboard", SecurityUtil.maskEmail(email));
            return DASHBOARD_REDIRECT;
        }

        if (success != null && !success.isBlank()) {
            model.addAttribute("success", success);
        }

        if (error != null && !error.isBlank()) {
            model.addAttribute("error", error);
        }

        log.debug("Showing login page - {}", SecurityUtil.createSecurityContext(request));
        return LOGIN_VIEW;
    }

    @PostMapping("/send-code")
    public String sendVerificationCode(
            @Valid @ModelAttribute final SendCodeRequest request,
            final BindingResult bindingResult,
            final HttpServletRequest httpRequest,
            final Model model) {

        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Please enter a valid email address");
            return LOGIN_VIEW;
        }

        final String clientIp = SecurityUtil.getClientIpAddress(httpRequest);
        final String sanitizedEmail = SecurityUtil.sanitizeEmail(request.getEmail());

        log.info("Verification code request from: {} (IP: {})",
                SecurityUtil.maskEmail(sanitizedEmail), clientIp);

        if (!SecurityUtil.isValidEmail(sanitizedEmail)) {
            model.addAttribute("error", "Please enter a valid email address");
            return LOGIN_VIEW;
        }

        try {
            authenticationService.sendVerificationCode(sanitizedEmail, clientIp);
            model.addAttribute("email", sanitizedEmail);
            log.info("Verification code sent successfully to: {}", SecurityUtil.maskEmail(sanitizedEmail));
            return VERIFY_VIEW;

        } catch (final RateLimitExceededException e) {
            return handleRateLimitError(model, sanitizedEmail, clientIp, e);
        } catch (final AuthenticationException e) {
            return handleAuthenticationError(model, sanitizedEmail, clientIp, e);
        } catch (final Exception e) {
            return handleUnexpectedError(model, sanitizedEmail, clientIp, e);
        }
    }

    @PostMapping("/verify")
    public String verifyCode(
            @Valid @ModelAttribute final VerifyCodeRequest request,
            final BindingResult bindingResult,
            final HttpServletRequest httpRequest,
            final HttpServletResponse httpResponse,
            final HttpSession session,
            final Model model) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Please enter a valid 6-digit verification code");
            model.addAttribute("email", request.getEmail());
            return VERIFY_VIEW;
        }

        final String clientIp = SecurityUtil.getClientIpAddress(httpRequest);
        final String sanitizedEmail = SecurityUtil.sanitizeEmail(request.getEmail());
        final String sanitizedCode = SecurityUtil.sanitizeVerificationCode(request.getCode());

        log.info("Verify code attempt for email: {} from: {}",
                SecurityUtil.maskEmail(sanitizedEmail), clientIp);

        if (!SecurityUtil.isValidEmail(sanitizedEmail) || !SecurityUtil.isValidVerificationCode(sanitizedCode)) {
            model.addAttribute("error", "Invalid email or verification code format");
            model.addAttribute("email", sanitizedEmail);
            return VERIFY_VIEW;
        }

        try {
            return authenticationService.verifyCodeAndAuthenticate(sanitizedEmail, sanitizedCode, clientIp)
                    .map(user -> handleSuccessfulAuthentication(user, session, httpRequest, httpResponse))
                    .orElseGet(() -> handleFailedAuthentication(model, sanitizedEmail));

        } catch (final RateLimitExceededException e) {
            return handleVerificationRateLimit(model, sanitizedEmail, e);
        } catch (final AuthenticationException e) {
            return handleVerificationError(model, sanitizedEmail, e);
        } catch (final Exception e) {
            return handleVerificationUnexpectedError(model, sanitizedEmail, clientIp, e);
        }
    }

    @GetMapping("/logout")
    public String logout(final HttpSession session, final HttpServletRequest request) {
        final String email = sessionManagementService.getUserEmail(session);
        final String clientIp = SecurityUtil.getClientIpAddress(request);

        if (email != null) {
            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                    email,
                    "User logged out",
                    clientIp
            );
            log.info("User logged out: {} from: {}", SecurityUtil.maskEmail(email), clientIp);
        }

        sessionManagementService.invalidateSession(session);
        return LOGIN_REDIRECT;
    }

    private String handleSuccessfulAuthentication(final User user, final HttpSession session, final HttpServletRequest request, final HttpServletResponse response) {
        final String clientIp = SecurityUtil.getClientIpAddress(request);

        log.info("Authentication successful for user: {} from: {}",
                SecurityUtil.maskEmail(user.getEmail()), clientIp);

        boolean sessionSetup = sessionManagementService.setupAuthenticatedSession(session, user, request, response);

        if (!sessionSetup) {
            log.error("Failed to setup authenticated session for user: {}", SecurityUtil.maskEmail(user.getEmail()));
            return "redirect:/auth/verify?error=session";
        }

        securityAuditService.logSecurityEvent(
                SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                user.getEmail(),
                "User logged in successfully",
                clientIp
        );

        log.info("Session setup successful, redirecting to dashboard for user: {}",
                SecurityUtil.maskEmail(user.getEmail()));

        return DASHBOARD_REDIRECT;
    }

    private String handleFailedAuthentication(final Model model, final String email) {
        log.warn("Authentication failed for email: {}", SecurityUtil.maskEmail(email));
        model.addAttribute("error", "Invalid or expired verification code");
        model.addAttribute("email", email);
        return VERIFY_VIEW;
    }

    private String handleRateLimitError(final Model model, final String email, final String clientIp, final RateLimitExceededException e) {
        model.addAttribute("error", "Too many requests. Please wait before trying again.");
        log.warn("Rate limit exceeded for email: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp);
        return LOGIN_VIEW;
    }

    private String handleAuthenticationError(final Model model, final String email, final String clientIp, final AuthenticationException e) {
        if (e.getMessage().contains("locked")) {
            model.addAttribute("error", "Your account is temporarily locked due to multiple failed verification attempts. Please wait or contact support.");
            log.warn("Account locked error for email: {} from IP: {}: {}", SecurityUtil.maskEmail(email), clientIp, e.getMessage());
        } else {
            model.addAttribute("error", "Unable to send verification code. Please check your email and try again.");
            log.warn("Authentication error for email: {} from IP: {}: {}", SecurityUtil.maskEmail(email), clientIp, e.getMessage());
        }
        return LOGIN_VIEW;
    }

    private String handleUnexpectedError(final Model model, final String email, final String clientIp, final Exception e) {
        model.addAttribute("error", "An unexpected error occurred. Please try again.");
        log.error("Unexpected error sending verification code for email: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
        return LOGIN_VIEW;
    }

    private String handleVerificationRateLimit(final Model model, final String email, final RateLimitExceededException e) {
        model.addAttribute("error", "Too many verification attempts. Please request a new code.");
        model.addAttribute("email", email);
        return VERIFY_VIEW;
    }

    private String handleVerificationError(final Model model, final String email, final AuthenticationException e) {
        if (e.getMessage().contains("locked")) {
            model.addAttribute("error", "Your account is temporarily locked. Please wait or contact support.");
        } else {
            model.addAttribute("error", "Verification failed. Please try again or request a new code.");
        }
        model.addAttribute("email", email);
        return VERIFY_VIEW;
    }

    private String handleVerificationUnexpectedError(final Model model, final String email, final String clientIp, final Exception e) {
        model.addAttribute("error", "An unexpected error occurred. Please try again.");
        model.addAttribute("email", email);
        log.error("Unexpected error during verification for email: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
        return VERIFY_VIEW;
    }
}