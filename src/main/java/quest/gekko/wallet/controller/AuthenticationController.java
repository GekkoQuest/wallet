package quest.gekko.wallet.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import quest.gekko.wallet.exception.AuthenticationException;
import quest.gekko.wallet.exception.RateLimitExceededException;
import quest.gekko.wallet.service.AuthenticationService;
import quest.gekko.wallet.service.SecurityAuditService;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final SecurityAuditService auditService;

    @GetMapping("/")
    public String loginPage(HttpSession session) {
        String email = (String) session.getAttribute("email");
        log.info("Login page access - email in session: {}", email != null ? "present" : "null");

        // If user is already authenticated, redirect to dashboard
        if (email != null) {
            log.info("User already authenticated, redirecting to dashboard");
            return "redirect:/dashboard";
        }
        return "login";
    }

    @PostMapping("/send-code")
    public String sendVerificationCode(
            @RequestParam String email,
            HttpServletRequest request,
            Model model) {

        String clientIp = getClientIpAddress(request);

        try {
            // Manual validation for now
            if (email == null || email.trim().isEmpty() || !isValidEmail(email.trim())) {
                model.addAttribute("error", "Please enter a valid email address");
                return "login";
            }

            String cleanEmail = email.trim().toLowerCase();
            authenticationService.sendVerificationCode(cleanEmail, clientIp);
            model.addAttribute("email", cleanEmail);
            return "verify";

        } catch (RateLimitExceededException e) {
            model.addAttribute("error", "Too many requests. Please wait before trying again.");
            log.warn("Rate limit exceeded for email: {} from IP: {}", email, clientIp);
            return "login";

        } catch (AuthenticationException e) {
            model.addAttribute("error", "Unable to send verification code. Please check your email and try again.");
            log.warn("Authentication error for email: {} from IP: {}: {}", email, clientIp, e.getMessage());
            return "login";

        } catch (Exception e) {
            model.addAttribute("error", "An unexpected error occurred. Please try again.");
            log.error("Unexpected error sending verification code for email: {} from IP: {}", email, clientIp, e);
            return "login";
        }
    }

    @PostMapping("/verify")
    public String verifyCode(
            @RequestParam String email,
            @RequestParam String code,
            HttpServletRequest request,
            HttpSession session,
            Model model) {

        String clientIp = getClientIpAddress(request);
        log.info("Verify code attempt for email: {}", maskEmail(email));

        try {
            // Manual validation for now.
            if (code == null || code.trim().isEmpty() || !isValidVerificationCode(code.trim())) {
                model.addAttribute("error", "Please enter a valid 6-digit verification code");
                model.addAttribute("email", email);
                return "verify";
            }

            String cleanEmail = email.trim().toLowerCase();
            String cleanCode = code.trim();

            return authenticationService.verifyCodeAndAuthenticate(cleanEmail, cleanCode, clientIp)
                    .map(user -> {
                        log.info("Authentication successful for user: {}", maskEmail(user.getEmail()));

                        // Clear any existing session data first
                        session.removeAttribute("email");
                        session.removeAttribute("userId");
                        session.removeAttribute("loginTime");

                        // Set new session attributes
                        session.setAttribute("email", user.getEmail());
                        session.setAttribute("userId", user.getId());
                        session.setAttribute("loginTime", System.currentTimeMillis());
                        session.setMaxInactiveInterval(30 * 60); // 30 minutes

                        log.info("Session created - ID: {}, Email: {}, UserId: {}",
                                session.getId(),
                                maskEmail(user.getEmail()),
                                user.getId());

                        // Log successful authentication
                        auditService.logSecurityEvent(
                                SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                                user.getEmail(),
                                "User logged in successfully",
                                clientIp
                        );

                        return "redirect:/dashboard";
                    })
                    .orElseGet(() -> {
                        log.warn("Authentication failed for email: {}", maskEmail(email));
                        model.addAttribute("error", "Invalid or expired verification code");
                        model.addAttribute("email", email);
                        return "verify";
                    });

        } catch (RateLimitExceededException e) {
            model.addAttribute("error", "Too many verification attempts. Please request a new code.");
            model.addAttribute("email", email);
            return "verify";

        } catch (AuthenticationException e) {
            model.addAttribute("error", "Verification failed. Please try again or request a new code.");
            model.addAttribute("email", email);
            return "verify";

        } catch (Exception e) {
            model.addAttribute("error", "An unexpected error occurred. Please try again.");
            model.addAttribute("email", email);
            log.error("Unexpected error during verification for email: {} from IP: {}", email, clientIp, e);
            return "verify";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpSession session, HttpServletRequest request) {
        String email = (String) session.getAttribute("email");
        String clientIp = getClientIpAddress(request);

        if (email != null) {
            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                    email,
                    "User logged out",
                    clientIp
            );
        }

        // Invalidate session securely
        try {
            session.invalidate();
        } catch (Exception e) {
            log.warn("Session invalidation failed during logout: {}", e.getMessage());
        }

        return "redirect:/";
    }

    private boolean isValidEmail(String email) {
        return email != null &&
                email.contains("@") &&
                email.contains(".") &&
                email.length() > 5 &&
                email.length() <= 254 &&
                email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    }

    private boolean isValidVerificationCode(String code) {
        return code != null &&
                code.length() == 6 &&
                code.matches("\\d{6}");
    }

    /**
     * Extract client IP address from request, considering proxy headers
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Masks email for logging privacy
     */
    private String maskEmail(String email) {
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
}