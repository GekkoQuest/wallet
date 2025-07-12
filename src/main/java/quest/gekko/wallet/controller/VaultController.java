package quest.gekko.wallet.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import quest.gekko.wallet.dto.request.EditPasswordRequest;
import quest.gekko.wallet.dto.request.SavePasswordRequest;
import quest.gekko.wallet.dto.response.PasswordEntryResponse;
import quest.gekko.wallet.dto.response.VaultStatisticsResponse;
import quest.gekko.wallet.entity.PasswordEntry;
import quest.gekko.wallet.service.PasswordManagementService;
import quest.gekko.wallet.service.SecurityAuditService;
import quest.gekko.wallet.service.SessionManagementService;
import quest.gekko.wallet.util.SecurityUtil;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
@Slf4j
public class VaultController {
    private static final String DASHBOARD_VIEW = "dashboard";
    private static final String LOGIN_REDIRECT = "redirect:/";
    private static final String DASHBOARD_REDIRECT = "redirect:/dashboard";

    private final PasswordManagementService passwordManagementService;
    private final SecurityAuditService securityAuditService;
    private final SessionManagementService sessionManagementService;

    @GetMapping("/dashboard")
    public String showDashboard(final HttpSession session, final HttpServletRequest request, final Model model) {
        log.debug("Dashboard access attempt - Session ID: {}", session.getId());

        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            log.warn("No valid session - redirecting to login");
            return LOGIN_REDIRECT;
        }

        try {
            final List<PasswordEntryResponse> passwords = passwordManagementService.getPasswordsByEmail(email)
                    .stream()
                    .map(PasswordEntryResponse::fromEntity)
                    .collect(Collectors.toList());

            final VaultStatisticsResponse statistics = passwordManagementService.getVaultStatistics(email);

            model.addAttribute("passwords", passwords);
            model.addAttribute("statistics", statistics);
            model.addAttribute("remainingSessionTime", sessionManagementService.getRemainingSessionTimeMinutes(session));

            final String clientIp = SecurityUtil.getClientIpAddress(request);
            securityAuditService.logPasswordAccess(email, clientIp, "Dashboard accessed");

            log.info("Dashboard loaded successfully for user: {} with {} passwords", SecurityUtil.maskEmail(email), passwords.size());
            return DASHBOARD_VIEW;
        } catch (final Exception e) {
            log.error("Error loading dashboard for user: {}", SecurityUtil.maskEmail(email), e);
            model.addAttribute("error", "Unable to load password vault");
            return DASHBOARD_VIEW;
        }
    }

    @PostMapping("/generate")
    public String savePassword(
            @Valid @ModelAttribute final SavePasswordRequest request,
            final BindingResult bindingResult,
            final HttpSession session,
            final HttpServletRequest httpRequest,
            final RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("error", "Invalid password data provided");
            return DASHBOARD_REDIRECT;
        }

        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            return LOGIN_REDIRECT;
        }

        final String clientIp = SecurityUtil.getClientIpAddress(httpRequest);

        try {
            passwordManagementService.savePassword(
                    email,
                    request.getName().trim(),
                    request.getEncrypted(),
                    request.getIv(),
                    request.getSalt()
            );

            securityAuditService.logPasswordAccess(email, clientIp, "Password saved: " + request.getName().trim());
            redirectAttributes.addFlashAttribute("success", "Password saved successfully");

            log.info("Password saved successfully for user: {} with name: {}",
                    SecurityUtil.maskEmail(email), request.getName().trim());

            sessionManagementService.updateSessionActivity(session);
            return DASHBOARD_REDIRECT;

        } catch (final Exception e) {
            log.error("Error saving password for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to save password: " + e.getMessage());
            return DASHBOARD_REDIRECT;
        }
    }

    @PostMapping("/edit")
    public String editPassword(
            @Valid @ModelAttribute final EditPasswordRequest request,
            final BindingResult bindingResult,
            final HttpSession session,
            final HttpServletRequest httpRequest,
            final RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("error", "Invalid password update data provided");
            return DASHBOARD_REDIRECT;
        }

        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            return LOGIN_REDIRECT;
        }

        final String clientIp = SecurityUtil.getClientIpAddress(httpRequest);

        try {
            passwordManagementService.editPassword(
                    request.getId(),
                    request.getEncrypted(),
                    request.getIv(),
                    request.getSalt(),
                    email
            );

            securityAuditService.logPasswordAccess(email, clientIp, "Password edited: " + request.getId());
            redirectAttributes.addFlashAttribute("success", "Password updated successfully");

            log.info("Password edited successfully for user: {} with ID: {}",
                    SecurityUtil.maskEmail(email), request.getId());

            sessionManagementService.updateSessionActivity(session);
            return DASHBOARD_REDIRECT;
        } catch (final SecurityException e) {
            log.warn("Unauthorized password edit attempt by user: {} for ID: {} from IP: {}",
                    SecurityUtil.maskEmail(email), request.getId(), clientIp);

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unauthorized password edit attempt: " + request.getId(),
                    clientIp
            );

            redirectAttributes.addFlashAttribute("error", "Unauthorized access");
            return DASHBOARD_REDIRECT;
        } catch (final Exception e) {
            log.error("Error editing password for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to update password: " + e.getMessage());
            return DASHBOARD_REDIRECT;
        }
    }

    @PostMapping("/delete")
    public String deletePassword(
            @RequestParam("id") final String passwordId,
            final HttpSession session,
            final HttpServletRequest httpRequest,
            final RedirectAttributes redirectAttributes) {
        if (passwordId == null || passwordId.trim().isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Invalid password ID");
            return DASHBOARD_REDIRECT;
        }

        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            return LOGIN_REDIRECT;
        }

        final String clientIp = SecurityUtil.getClientIpAddress(httpRequest);

        try {
            passwordManagementService.deletePassword(passwordId.trim(), email);

            securityAuditService.logPasswordAccess(email, clientIp, "Password deleted: " + passwordId.trim());
            redirectAttributes.addFlashAttribute("success", "Password deleted successfully");

            log.info("Password deleted successfully for user: {} with ID: {}",
                    SecurityUtil.maskEmail(email), passwordId.trim());

            sessionManagementService.updateSessionActivity(session);
            return DASHBOARD_REDIRECT;

        } catch (final SecurityException e) {
            log.warn("Unauthorized password deletion attempt by user: {} for ID: {} from IP: {}",
                    SecurityUtil.maskEmail(email), passwordId.trim(), clientIp);

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    "Unauthorized password deletion attempt: " + passwordId.trim(),
                    clientIp
            );

            redirectAttributes.addFlashAttribute("error", "Unauthorized access");
            return DASHBOARD_REDIRECT;
        } catch (final Exception e) {
            log.error("Error deleting password for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            redirectAttributes.addFlashAttribute("error", "Failed to delete password: " + e.getMessage());
            return DASHBOARD_REDIRECT;
        }
    }

    @GetMapping("/vault/statistics")
    @ResponseBody
    public VaultStatisticsResponse getVaultStatistics(final HttpSession session) {
        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            throw new SecurityException("User not authenticated");
        }

        sessionManagementService.updateSessionActivity(session);
        return passwordManagementService.getVaultStatistics(email);
    }

    @GetMapping("/vault/search")
    public String searchPasswords(
            @RequestParam(value = "query", required = false) final String searchQuery,
            final HttpSession session,
            final HttpServletRequest request,
            final Model model) {
        final String email = sessionManagementService.validateSessionAndGetEmail(session);

        if (email == null) {
            return LOGIN_REDIRECT;
        }

        try {
            final List<PasswordEntryResponse> passwords;

            if (searchQuery != null && !searchQuery.trim().isEmpty()) {
                passwords = passwordManagementService.searchPasswordsByName(email, searchQuery.trim())
                        .stream()
                        .map(PasswordEntryResponse::fromEntity)
                        .collect(Collectors.toList());

                final String clientIp = SecurityUtil.getClientIpAddress(request);
                securityAuditService.logPasswordAccess(email, clientIp, "Password search: " + searchQuery.trim());
            } else {
                passwords = passwordManagementService.getPasswordsByEmail(email)
                        .stream()
                        .map(PasswordEntryResponse::fromEntity)
                        .collect(Collectors.toList());
            }

            final VaultStatisticsResponse statistics = passwordManagementService.getVaultStatistics(email);

            model.addAttribute("passwords", passwords);
            model.addAttribute("statistics", statistics);
            model.addAttribute("searchQuery", searchQuery);
            model.addAttribute("remainingSessionTime", sessionManagementService.getRemainingSessionTimeMinutes(session));

            sessionManagementService.updateSessionActivity(session);

            return DASHBOARD_VIEW;
        } catch (final Exception e) {
            log.error("Error searching passwords for user: {}", SecurityUtil.maskEmail(email), e);
            model.addAttribute("error", "Unable to search password vault");
            return DASHBOARD_VIEW;
        }
    }
}