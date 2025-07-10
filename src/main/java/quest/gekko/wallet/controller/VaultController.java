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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import quest.gekko.wallet.entity.PasswordEntry;
import quest.gekko.wallet.service.PasswordService;
import quest.gekko.wallet.service.SecurityAuditService;

import java.util.List;

@Controller
@RequiredArgsConstructor
@Slf4j
public class VaultController {

    private final PasswordService passwordService;
    private final SecurityAuditService auditService;

    @GetMapping("/dashboard")
    public String showDashboard(HttpSession session, HttpServletRequest request, Model model) {
        log.info("=== DASHBOARD ACCESS ATTEMPT ===");
        log.info("Session ID: {}", session.getId());
        log.info("Session new: {}", session.isNew());

        String email = (String) session.getAttribute("email");
        String userId = (String) session.getAttribute("userId");
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        Long loginTime = (Long) session.getAttribute("loginTime");

        log.info("Session attributes - email: {}, userId: {}, authenticated: {}, loginTime: {}",
                email != null ? maskEmail(email) : "NULL",
                userId != null ? "present" : "NULL",
                authenticated,
                loginTime != null ? "present" : "NULL");

        // Just check if email exists
        if (email == null) {
            log.warn("No email in session - redirecting to login");
            return "redirect:/";
        }

        try {
            List<PasswordEntry> passwords = passwordService.getPasswordsByEmail(email);
            model.addAttribute("passwords", passwords);

            String clientIp = getClientIpAddress(request);
            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.PASSWORD_ACCESS,
                    email,
                    "Dashboard accessed",
                    clientIp
            );

            log.info("Dashboard loaded successfully for user: {} with {} passwords",
                    maskEmail(email), passwords.size());
            return "dashboard";

        } catch (Exception e) {
            log.error("Error loading dashboard for user: {}", maskEmail(email), e);
            model.addAttribute("error", "Unable to load password vault");
            return "dashboard";
        }
    }

    @PostMapping("/generate")
    public String savePassword(
            @RequestParam String name,
            @RequestParam String encrypted,
            @RequestParam String iv,
            @RequestParam String salt,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        String email = validateSessionAndGetEmail(session, request);
        if (email == null) {
            return "redirect:/";
        }

        String clientIp = getClientIpAddress(request);

        try {
            if (name == null || name.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Password name is required");
                return "redirect:/dashboard";
            }

            if (encrypted == null || encrypted.trim().isEmpty() ||
                    iv == null || iv.trim().isEmpty() ||
                    salt == null || salt.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Invalid password data");
                return "redirect:/dashboard";
            }

            passwordService.savePassword(email, name.trim(), encrypted, iv, salt);

            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.PASSWORD_ACCESS,
                    email,
                    "Password saved: " + name.trim(),
                    clientIp
            );

            redirectAttributes.addFlashAttribute("success", "Password saved successfully");
            return "redirect:/dashboard";

        } catch (Exception e) {
            log.error("Error saving password for user: {} from IP: {}", email, clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to save password");
            return "redirect:/dashboard";
        }
    }

    @PostMapping("/edit")
    public String editPassword(
            @RequestParam String id,
            @RequestParam String encrypted,
            @RequestParam String iv,
            @RequestParam String salt,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        String email = validateSessionAndGetEmail(session, request);
        if (email == null) {
            return "redirect:/";
        }

        String clientIp = getClientIpAddress(request);

        try {
            if (id == null || id.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Password ID is required");
                return "redirect:/dashboard";
            }

            if (encrypted == null || encrypted.trim().isEmpty() ||
                    iv == null || iv.trim().isEmpty() ||
                    salt == null || salt.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Invalid password data");
                return "redirect:/dashboard";
            }

            passwordService.editPassword(id, encrypted, iv, salt, email);

            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.PASSWORD_ACCESS,
                    email,
                    "Password edited: " + id,
                    clientIp
            );

            redirectAttributes.addFlashAttribute("success", "Password updated successfully");
            return "redirect:/dashboard";

        } catch (SecurityException e) {
            log.warn("Unauthorized password edit attempt by user: {} for ID: {} from IP: {}", email, id, clientIp);
            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unauthorized password edit attempt: " + id,
                    clientIp
            );
            redirectAttributes.addFlashAttribute("error", "Unauthorized access");
            return "redirect:/dashboard";

        } catch (Exception e) {
            log.error("Error editing password for user: {} from IP: {}", email, clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to update password");
            return "redirect:/dashboard";
        }
    }

    @PostMapping("/delete")
    public String deletePassword(
            @RequestParam String id,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        String email = validateSessionAndGetEmail(session, request);
        if (email == null) {
            return "redirect:/";
        }

        String clientIp = getClientIpAddress(request);

        try {
            if (id == null || id.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Password ID is required");
                return "redirect:/dashboard";
            }

            passwordService.deletePassword(id, email);

            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.PASSWORD_ACCESS,
                    email,
                    "Password deleted: " + id,
                    clientIp
            );

            redirectAttributes.addFlashAttribute("success", "Password deleted successfully");
            return "redirect:/dashboard";

        } catch (SecurityException e) {
            log.warn("Unauthorized password deletion attempt by user: {} for ID: {} from IP: {}", email, id, clientIp);
            auditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unauthorized password deletion attempt: " + id,
                    clientIp
            );
            redirectAttributes.addFlashAttribute("error", "Unauthorized access");
            return "redirect:/dashboard";

        } catch (Exception e) {
            log.error("Error deleting password for user: {} from IP: {}", email, clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to delete password");
            return "redirect:/dashboard";
        }
    }

    private String validateSessionAndGetEmail(HttpSession session, HttpServletRequest request) {
        String email = (String) session.getAttribute("email");

        log.debug("Session validation - email: {}",
                email != null ? maskEmail(email) : "null");

        // Just check if email exists
        if (email == null) {
            log.warn("Session validation failed - no email in session");
            return null;
        }

        return email;
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