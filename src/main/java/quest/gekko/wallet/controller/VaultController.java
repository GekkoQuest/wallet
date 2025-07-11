package quest.gekko.wallet.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import quest.gekko.wallet.entity.PasswordEntry;
import quest.gekko.wallet.service.PasswordManagementService;
import quest.gekko.wallet.service.SecurityAuditService;
import quest.gekko.wallet.util.SecurityUtil;

import java.util.List;

@Controller
@RequiredArgsConstructor
@Slf4j
@Validated
public class VaultController {
    private final PasswordManagementService passwordManagementService;
    private final SecurityAuditService securityAuditService;

    @GetMapping("/dashboard")
    public String showDashboard(final HttpSession session, final HttpServletRequest request, final Model model) {
        log.debug("Dashboard access attempt - Session ID: {}", session.getId());

        final String email = validateSessionAndGetEmail(session);

        if (email == null) {
            log.warn("No valid session - redirecting to login");
            return "redirect:/";
        }

        try {
            final List<PasswordEntry> passwords = passwordManagementService.getPasswordsByEmail(email);
            model.addAttribute("passwords", passwords);

            final String clientIp = SecurityUtil.getClientIpAddress(request);
            securityAuditService.logPasswordAccess(email, clientIp, "Dashboard accessed");

            log.info("Dashboard loaded successfully for user: {} with {} passwords", SecurityUtil.maskEmail(email), passwords.size());
            return "dashboard";

        } catch (final Exception e) {
            log.error("Error loading dashboard for user: {}", SecurityUtil.maskEmail(email), e);
            model.addAttribute("error", "Unable to load password vault");
            return "dashboard";
        }
    }

    @PostMapping("/generate")
    public String savePassword(
            @RequestParam @NotBlank final String name,
            @RequestParam @NotBlank final String encrypted,
            @RequestParam @NotBlank final String iv,
            @RequestParam @NotBlank final String salt,
            final HttpSession session,
            final HttpServletRequest request,
            final RedirectAttributes redirectAttributes) {
        final String email = validateSessionAndGetEmail(session);

        if (email == null) {
            return "redirect:/";
        }

        final String clientIp = SecurityUtil.getClientIpAddress(request);

        try {
            passwordManagementService.savePassword(email, name.trim(), encrypted, iv, salt);

            securityAuditService.logPasswordAccess(email, clientIp, "Password saved: " + name.trim());
            redirectAttributes.addFlashAttribute("success", "Password saved successfully");

            log.info("Password saved successfully for user: {}", SecurityUtil.maskEmail(email));
            return "redirect:/dashboard";
        } catch (final Exception e) {
            log.error("Error saving password for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to save password: " + e.getMessage());
            return "redirect:/dashboard";
        }
    }

    @PostMapping("/edit")
    public String editPassword(
            @RequestParam @NotBlank final String id,
            @RequestParam @NotBlank final String encrypted,
            @RequestParam @NotBlank final String iv,
            @RequestParam @NotBlank final String salt,
            final HttpSession session,
            final HttpServletRequest request,
            final RedirectAttributes redirectAttributes) {
        final String email = validateSessionAndGetEmail(session);

        if (email == null) {
            return "redirect:/";
        }

        final String clientIp = SecurityUtil.getClientIpAddress(request);

        try {
            passwordManagementService.editPassword(id, encrypted, iv, salt, email);

            securityAuditService.logPasswordAccess(email, clientIp, "Password edited: " + id);
            redirectAttributes.addFlashAttribute("success", "Password updated successfully");

            log.info("Password edited successfully for user: {}", SecurityUtil.maskEmail(email));
            return "redirect:/dashboard";
        } catch (final SecurityException e) {
            log.warn("Unauthorized password edit attempt by user: {} for ID: {} from IP: {}",
                    SecurityUtil.maskEmail(email), id, clientIp);
            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unauthorized password edit attempt: " + id,
                    clientIp
            );
            redirectAttributes.addFlashAttribute("error", "Unauthorized access");
            return "redirect:/dashboard";
        } catch (final Exception e) {
            log.error("Error editing password for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to update password: " + e.getMessage());
            return "redirect:/dashboard";
        }
    }

    @PostMapping("/delete")
    public String deletePassword(
            @RequestParam @NotBlank final String id,
            final HttpSession session,
            final HttpServletRequest request,
            final RedirectAttributes redirectAttributes) {
        final String email = validateSessionAndGetEmail(session);

        if (email == null) {
            return "redirect:/";
        }

        final String clientIp = SecurityUtil.getClientIpAddress(request);

        try {
            passwordManagementService.deletePassword(id, email);

            securityAuditService.logPasswordAccess(email, clientIp, "Password deleted: " + id);
            redirectAttributes.addFlashAttribute("success", "Password deleted successfully");

            log.info("Password deleted successfully for user: {}", SecurityUtil.maskEmail(email));
            return "redirect:/dashboard";
        } catch (final SecurityException e) {
            log.warn("Unauthorized password deletion attempt by user: {} for ID: {} from IP: {}",
                    SecurityUtil.maskEmail(email), id, clientIp);

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unauthorized password deletion attempt: " + id,
                    clientIp
            );

            redirectAttributes.addFlashAttribute("error", "Unauthorized access");
            return "redirect:/dashboard";
        } catch (final Exception e) {
            log.error("Error deleting password for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to delete password: " + e.getMessage());
            return "redirect:/dashboard";
        }
    }

    private String validateSessionAndGetEmail(final HttpSession session) {
        final String email = (String) session.getAttribute("email");
        final Long loginTime = (Long) session.getAttribute("loginTime");

        log.debug("Session validation - email: {}, loginTime: {}",
                email != null ? SecurityUtil.maskEmail(email) : "null",
                loginTime != null ? "present" : "null");

        if (email == null) {
            log.warn("Session validation failed - no email in session");
            return null;
        }

        // Maybe add session timeout validation?
        if (loginTime != null) {
            final long sessionAge = System.currentTimeMillis() - loginTime;
            final long maxSessionAge = 24 * 60 * 60 * 1000L; // 24 hours

            if (sessionAge > maxSessionAge) {
                log.warn("Session expired for user: {}", SecurityUtil.maskEmail(email));
                return null;
            }
        }

        return email;
    }
}