package quest.gekko.wallet.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import quest.gekko.wallet.entity.User;
import quest.gekko.wallet.exception.AuthenticationException;
import quest.gekko.wallet.exception.RateLimitExceededException;
import quest.gekko.wallet.service.AuthenticationService;
import quest.gekko.wallet.service.SecurityAuditService;
import quest.gekko.wallet.util.SecurityUtil;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final SecurityAuditService securityAuditService;

    @GetMapping("/")
    public String loginPage(final HttpSession session) {
        final String email = (String) session.getAttribute("email");
        log.debug("Login page access - email in session: {}", email != null ? "present" : "null");

        if (email != null) {
            log.info("User already authenticated, redirecting to dashboard");
            return "redirect:/dashboard";
        }

        return "login";
    }

    @PostMapping("/send-code")
    public String sendVerificationCode(@RequestParam @NotBlank @Email final String email, final HttpServletRequest request, final Model model) {
        final String clientIp = SecurityUtil.getClientIpAddress(request);
        final String sanitizedEmail = SecurityUtil.sanitizeEmail(email);

        if (!SecurityUtil.isValidEmail(sanitizedEmail)) {
            model.addAttribute("error", "Please enter a valid email address");
            return "login";
        }

        try {
            authenticationService.sendVerificationCode(sanitizedEmail, clientIp);
            model.addAttribute("email", sanitizedEmail);
            return "verify";

        } catch (final RateLimitExceededException e) {
            model.addAttribute("error", "Too many requests. Please wait before trying again.");
            log.warn("Rate limit exceeded for email: {} from IP: {}", SecurityUtil.maskEmail(sanitizedEmail), clientIp);
            return "login";

        } catch (final AuthenticationException e) {
            model.addAttribute("error", "Unable to send verification code. Please check your email and try again.");
            log.warn("Authentication error for email: {} from IP: {}: {}", SecurityUtil.maskEmail(sanitizedEmail), clientIp, e.getMessage());
            return "login";

        } catch (final Exception e) {
            model.addAttribute("error", "An unexpected error occurred. Please try again.");
            log.error("Unexpected error sending verification code for email: {} from IP: {}", SecurityUtil.maskEmail(sanitizedEmail), clientIp, e);
            return "login";
        }
    }

    @PostMapping("/verify")
    public String verifyCode(@RequestParam @NotBlank @Email final String email,
                             @RequestParam @NotBlank @Pattern(regexp = "^[0-9]{6}$", message = "Code must be 6 digits") final String code,
                             final HttpServletRequest request,
                             final HttpSession session,
                             final Model model) {
        final String clientIp = SecurityUtil.getClientIpAddress(request);
        final String sanitizedEmail = SecurityUtil.sanitizeEmail(email);
        final String sanitizedCode = SecurityUtil.sanitizeVerificationCode(code);

        log.info("Verify code attempt for email: {}", SecurityUtil.maskEmail(sanitizedEmail));

        if (!SecurityUtil.isValidEmail(sanitizedEmail) || !SecurityUtil.isValidVerificationCode(sanitizedCode)) {
            model.addAttribute("error", "Invalid email or verification code format");
            model.addAttribute("email", sanitizedEmail);
            return "verify";
        }

        try {
            return authenticationService.verifyCodeAndAuthenticate(sanitizedEmail, sanitizedCode, clientIp)
                    .map(user -> {
                        log.info("Authentication successful for user: {}", SecurityUtil.maskEmail(user.getEmail()));

                        createUserSession(session, user);

                        securityAuditService.logSecurityEvent(
                                SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                                user.getEmail(),
                                "User logged in successfully",
                                clientIp
                        );

                        return "redirect:/dashboard";
                    })
                    .orElseGet(() -> {
                        log.warn("Authentication failed for email: {}", SecurityUtil.maskEmail(sanitizedEmail));
                        model.addAttribute("error", "Invalid or expired verification code");
                        model.addAttribute("email", sanitizedEmail);
                        return "verify";
                    });

        } catch (final RateLimitExceededException e) {
            model.addAttribute("error", "Too many verification attempts. Please request a new code.");
            model.addAttribute("email", sanitizedEmail);
            return "verify";
        } catch (final AuthenticationException e) {
            model.addAttribute("error", "Verification failed. Please try again or request a new code.");
            model.addAttribute("email", sanitizedEmail);
            return "verify";
        } catch (final Exception e) {
            model.addAttribute("error", "An unexpected error occurred. Please try again.");
            model.addAttribute("email", sanitizedEmail);
            log.error("Unexpected error during verification for email: {} from IP: {}", SecurityUtil.maskEmail(sanitizedEmail), clientIp, e);
            return "verify";
        }
    }

    @GetMapping("/logout")
    public String logout(final HttpSession session, final HttpServletRequest request) {
        final String email = (String) session.getAttribute("email");
        final String clientIp = SecurityUtil.getClientIpAddress(request);

        if (email != null) {
            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                    email,
                    "User logged out",
                    clientIp
            );
        }

        invalidateSession(session);
        return "redirect:/";
    }

    private void createUserSession(final HttpSession session, final User user) {
        // Clear any existing session data first
        session.invalidate();

        // Set session attributes
        session.setAttribute("email", user.getEmail());
        session.setAttribute("userId", user.getId());
        session.setAttribute("loginTime", System.currentTimeMillis());
        session.setMaxInactiveInterval(30 * 60); // 30 minutes

        log.info("Session created - ID: {}, Email: {}, UserId: {}",
                session.getId(),
                SecurityUtil.maskEmail(user.getEmail()),
                user.getId());
    }

    private void invalidateSession(final HttpSession session) {
        try {
            session.invalidate();
        } catch (final IllegalStateException e) {
            log.warn("Session already invalidated during logout: {}", e.getMessage());
        } catch (final Exception e) {
            log.warn("Session invalidation failed during logout: {}", e.getMessage());
        }
    }
}