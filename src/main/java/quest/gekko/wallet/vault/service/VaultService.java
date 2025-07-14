package quest.gekko.wallet.vault.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import quest.gekko.wallet.common.config.properties.ApplicationProperties;
import quest.gekko.wallet.vault.dto.response.VaultStatisticsResponse;
import quest.gekko.wallet.vault.entity.PasswordEntry;
import quest.gekko.wallet.vault.exception.VaultAccessException;
import quest.gekko.wallet.common.exception.InputValidationException;
import quest.gekko.wallet.vault.repository.PasswordEntryRepository;
import quest.gekko.wallet.validation.service.InputSanitizationService;
import quest.gekko.wallet.security.util.SecurityUtil;
import quest.gekko.wallet.authentication.service.EmailService;
import quest.gekko.wallet.audit.service.SecurityAuditService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class VaultService {
    private final PasswordEntryRepository passwordEntryRepository;
    private final InputSanitizationService inputSanitizationService;
    private final ApplicationProperties applicationProperties;
    private final EmailService emailService;
    private final SecurityAuditService securityAuditService;

    private final ConcurrentHashMap<String, Integer> failedUnlockAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LocalDateTime> lastUnlockAttempt = new ConcurrentHashMap<>();
    private static final int MAX_FAILED_UNLOCK_ATTEMPTS = 5;
    private static final int UNLOCK_ATTEMPT_WINDOW_MINUTES = 15;

    @Transactional
    public void savePassword(final String email, final String serviceName, final String username,
                             final String encrypted, final String iv, final String salt) {
        validatePasswordInputs(email, serviceName, username, encrypted, iv, salt);

        final long existingCount = passwordEntryRepository.countByEmail(email);
        final long maxAllowed = applicationProperties.getVault().getMaxPasswordsPerUser();

        if (existingCount >= maxAllowed) {
            emailService.sendSecurityAlert(
                    email,
                    "Vault Limit Reached",
                    String.format("Maximum password limit of %d reached. Unable to save new passwords.", maxAllowed),
                    "system"
            );

            throw new VaultAccessException(
                    String.format("Maximum number of passwords reached (%d/%d) for this account", existingCount, maxAllowed)
            );
        }

        final String sanitizedServiceName = inputSanitizationService.sanitizePasswordName(serviceName);
        if (sanitizedServiceName == null || sanitizedServiceName.trim().isEmpty()) {
            throw new InputValidationException("Invalid service name provided");
        }

        final String sanitizedUsername = username != null ?
                inputSanitizationService.sanitizeString(username, 200) : null;

        try {
            final PasswordEntry entry = PasswordEntry.builder()
                    .email(email)
                    .serviceName(sanitizedServiceName)
                    .username(sanitizedUsername)
                    .encrypted(encrypted)
                    .iv(iv)
                    .salt(salt)
                    .createdAt(LocalDateTime.now())
                    .accessCount(0)
                    .build();

            final PasswordEntry savedEntry = passwordEntryRepository.save(entry);
            log.info("Password entry created for user: {} with service: {} (ID: {})",
                    SecurityUtil.maskEmail(email), sanitizedServiceName, savedEntry.getId());
        } catch (final Exception e) {
            log.error("Failed to save password for user: {}", SecurityUtil.maskEmail(email), e);
            throw new VaultAccessException("Failed to save password entry", e);
        }
    }

    @Transactional
    public void editPassword(String id, String username, String encrypted, String iv, String salt, String email) {
        validateEditInputs(id, username, encrypted, iv, salt, email);

        try {
            final Optional<PasswordEntry> entryOpt = passwordEntryRepository.findByIdAndEmail(id, email);

            if (entryOpt.isEmpty()) {
                log.warn("Unauthorized password edit attempt by user: {} for ID: {}", SecurityUtil.maskEmail(email), id);

                emailService.sendSecurityAlert(
                        email,
                        "Unauthorized Password Edit Attempt",
                        String.format("Someone attempted to edit a password entry (ID: %s) that doesn't belong to your account.", id),
                        "system"
                );

                throw new SecurityException("Password not found or access denied");
            }

            final PasswordEntry entry = entryOpt.get();
            final String sanitizedUsername = username != null ?
                    inputSanitizationService.sanitizeString(username, 200) : null;

            entry.recordAccess();

            entry.setUsername(sanitizedUsername);
            entry.setEncrypted(encrypted);
            entry.setIv(iv);
            entry.setSalt(salt);
            entry.recordModification();

            final PasswordEntry savedEntry = passwordEntryRepository.save(entry);
            log.info("Password entry updated for user: {} with ID: {} (service: {})",
                    SecurityUtil.maskEmail(email), id, savedEntry.getServiceName());
        } catch (SecurityException e) {
            throw e;
        } catch (final Exception e) {
            log.error("Failed to edit password for user: {} with ID: {}", SecurityUtil.maskEmail(email), id, e);
            throw new VaultAccessException("Failed to update password entry", e);
        }
    }

    @Transactional
    public void deletePassword(final String id, final String email) {
        validateDeleteInputs(id, email);

        try {
            final Optional<PasswordEntry> entryOpt = passwordEntryRepository.findByIdAndEmail(id, email);

            if (entryOpt.isEmpty()) {
                log.warn("Unauthorized password deletion attempt by user: {} for ID: {}", SecurityUtil.maskEmail(email), id);

                emailService.sendSecurityAlert(
                        email,
                        "Unauthorized Password Deletion Attempt",
                        String.format("Someone attempted to delete a password entry (ID: %s) that doesn't belong to your account.", id),
                        "system"
                );

                throw new SecurityException("Password not found or access denied");
            }

            final PasswordEntry entry = entryOpt.get();
            passwordEntryRepository.delete(entry);

            log.info("Password entry deleted for user: {} with ID: {} (service: {})",
                    SecurityUtil.maskEmail(email), id, entry.getServiceName());
        } catch (final SecurityException e) {
            throw e;
        } catch (final Exception e) {
            log.error("Failed to delete password for user: {} with ID: {}", SecurityUtil.maskEmail(email), id, e);
            throw new VaultAccessException("Failed to delete password entry", e);
        }
    }

    public void recordFailedUnlockAttempt(final String email, final String clientIp) {
        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime windowStart = now.minusMinutes(UNLOCK_ATTEMPT_WINDOW_MINUTES);

        final LocalDateTime lastAttempt = lastUnlockAttempt.get(email);
        if (lastAttempt != null && lastAttempt.isBefore(windowStart)) {
            failedUnlockAttempts.remove(email);
            lastUnlockAttempt.remove(email);
        }

        final int attempts = failedUnlockAttempts.merge(email, 1, Integer::sum);
        lastUnlockAttempt.put(email, now);

        log.warn("Failed unlock attempt #{} for user: {} from IP: {}", attempts, SecurityUtil.maskEmail(email), clientIp);

        if (attempts >= MAX_FAILED_UNLOCK_ATTEMPTS) {
            emailService.sendSecurityAlert(
                    email,
                    "Multiple Failed Master Password Attempts",
                    String.format("We detected %d failed master password attempts in the last %d minutes from IP address %s. " +
                                    "If this wasn't you, your account may be under attack. Consider changing your master password.",
                            attempts, UNLOCK_ATTEMPT_WINDOW_MINUTES, clientIp),
                    clientIp
            );

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    String.format("Too many failed unlock attempts: %d in %d minutes", attempts, UNLOCK_ATTEMPT_WINDOW_MINUTES),
                    clientIp
            );
        }
    }

    public void recordSuccessfulUnlock(final String email) {
        failedUnlockAttempts.remove(email);
        lastUnlockAttempt.remove(email);
    }

    @Transactional(readOnly = true)
    public List<PasswordEntry> getPasswordsByEmail(final String email) {
        validateEmailInput(email);

        try {
            final List<PasswordEntry> entries = passwordEntryRepository.findByEmailOrderByCreatedAtDesc(email);
            log.debug("Retrieved {} password entries for user: {}", entries.size(), SecurityUtil.maskEmail(email));
            return entries;
        } catch (final Exception e) {
            log.error("Failed to retrieve passwords for user: {}", SecurityUtil.maskEmail(email), e);
            throw new VaultAccessException("Failed to load password vault", e);
        }
    }

    @Transactional(readOnly = true)
    public List<PasswordEntry> searchPasswordsByName(String email, String searchPattern) {
        validateEmailInput(email);

        if (searchPattern == null || searchPattern.trim().isEmpty()) {
            return getPasswordsByEmail(email);
        }

        try {
            final String sanitizedPattern = inputSanitizationService.sanitizePasswordName(searchPattern);

            if (sanitizedPattern == null || sanitizedPattern.trim().isEmpty()) {
                log.debug("Invalid search pattern, returning all passwords for user: {}", SecurityUtil.maskEmail(email));
                return getPasswordsByEmail(email);
            }

            final List<PasswordEntry> entries = passwordEntryRepository.findByEmailAndServiceNameOrUsernameContainingIgnoreCase(email, sanitizedPattern);

            log.debug("Found {} password entries matching pattern '{}' for user: {}",
                    entries.size(), sanitizedPattern, SecurityUtil.maskEmail(email));
            return entries;

        } catch (final Exception e) {
            log.error("Failed to search passwords for user: {} with pattern: {}", SecurityUtil.maskEmail(email), searchPattern, e);
            throw new VaultAccessException("Failed to search password vault", e);
        }
    }

    @Transactional(readOnly = true)
    public List<PasswordEntry> getRecentlyAccessedPasswords(final String email, final int hours) {
        validateEmailInput(email);

        try {
            final LocalDateTime since = LocalDateTime.now().minusHours(hours);
            final List<PasswordEntry> entries = passwordEntryRepository.findRecentlyAccessedByEmail(email, since);
            log.debug("Found {} recently accessed password entries for user: {} (last {} hours)",
                    entries.size(), SecurityUtil.maskEmail(email), hours);
            return entries;
        } catch (final Exception e) {
            log.error("Failed to get recently accessed passwords for user: {}", SecurityUtil.maskEmail(email), e);
            throw new VaultAccessException("Failed to load recent password access", e);
        }
    }

    @Transactional
    public void recordPasswordAccess(final String passwordId, final String email) {
        try {
            final Optional<PasswordEntry> entryOpt = passwordEntryRepository.findByIdAndEmail(passwordId, email);

            if (entryOpt.isPresent()) {
                final PasswordEntry entry = entryOpt.get();
                entry.recordAccess();
                passwordEntryRepository.save(entry);
                log.debug("Recorded access for password ID: {} by user: {} (service: {})",
                        passwordId, SecurityUtil.maskEmail(email), entry.getServiceName());
            } else {
                log.warn("Attempted to record access for non-existent or unauthorized password ID: {} by user: {}",
                        passwordId, SecurityUtil.maskEmail(email));
            }
        } catch (final Exception e) {
            log.warn("Failed to record password access for user: {} and ID: {}", SecurityUtil.maskEmail(email), passwordId, e);
        }
    }

    @Transactional(readOnly = true)
    public VaultStatisticsResponse getVaultStatistics(final String email) {
        validateEmailInput(email);

        try {
            final long totalPasswords = passwordEntryRepository.countByEmail(email);
            final LocalDateTime past24Hours = LocalDateTime.now().minusHours(24);
            final List<PasswordEntry> recentAccess = passwordEntryRepository.findRecentlyAccessedByEmail(email, past24Hours);
            final long maxPasswordsAllowed = applicationProperties.getVault().getMaxPasswordsPerUser();

            final VaultStatisticsResponse statistics = VaultStatisticsResponse.fromStatistics(
                    totalPasswords,
                    recentAccess.size(),
                    maxPasswordsAllowed
            );

            log.debug("Vault statistics for user: {} - Total: {}, Recent: {}, Usage: {}%",
                    SecurityUtil.maskEmail(email),
                    totalPasswords,
                    recentAccess.size(),
                    String.format("%.1f", statistics.getUsagePercentage()));

            return statistics;
        } catch (final Exception e) {
            log.error("Failed to get vault statistics for user: {}", SecurityUtil.maskEmail(email), e);
            throw new VaultAccessException("Failed to load vault statistics", e);
        }
    }

    @Transactional(readOnly = true)
    public Optional<PasswordEntry> getPasswordById(final String id, final String email) {
        validateEmailInput(email);

        if (id == null || id.trim().isEmpty()) {
            throw new InputValidationException("Password ID is required");
        }

        try {
            return passwordEntryRepository.findByIdAndEmail(id, email);
        } catch (final Exception e) {
            log.error("Failed to get password by ID for user: {} with ID: {}", SecurityUtil.maskEmail(email), id, e);
            throw new VaultAccessException("Failed to retrieve password entry", e);
        }
    }

    @Transactional(readOnly = true)
    public boolean isVaultNearLimit(final String email) {
        try {
            final VaultStatisticsResponse stats = getVaultStatistics(email);
            return stats.isNearLimit();
        } catch (final Exception e) {
            log.warn("Failed to check vault limit for user: {}", SecurityUtil.maskEmail(email), e);
            return false;
        }
    }

    @Transactional(readOnly = true)
    public long getRemainingPasswordSlots(final String email) {
        try {
            final long currentCount = passwordEntryRepository.countByEmail(email);
            final long maxAllowed = applicationProperties.getVault().getMaxPasswordsPerUser();
            return Math.max(0, maxAllowed - currentCount);
        } catch (final Exception e) {
            log.warn("Failed to get remaining password slots for user: {}", SecurityUtil.maskEmail(email), e);
            return 0;
        }
    }

    private void validatePasswordInputs(final String email, final String serviceName, final String username,
                                        final String encrypted, final String iv, final String salt) {
        validateEmailInput(email);

        if (serviceName == null || serviceName.trim().isEmpty()) {
            throw new InputValidationException("Service name is required");
        }

        if (serviceName.length() > applicationProperties.getVault().getMaxPasswordNameLength()) {
            throw new InputValidationException("Service name is too long (max " +
                    applicationProperties.getVault().getMaxPasswordNameLength() + " characters)");
        }

        if (!inputSanitizationService.isValidPasswordName(serviceName)) {
            throw new InputValidationException("Invalid service name format");
        }

        if (username != null && username.length() > 200) {
            throw new InputValidationException("Username is too long (max 200 characters)");
        }

        validateEncryptionData(encrypted, iv, salt);
    }

    private void validateEditInputs(final String id, final String username, final String encrypted,
                                    final String iv, final String salt, final String email) {
        if (id == null || id.trim().isEmpty()) {
            throw new InputValidationException("Password ID is required");
        }

        if (username != null && username.length() > 200) {
            throw new InputValidationException("Username is too long (max 200 characters)");
        }

        validateEmailInput(email);
        validateEncryptionData(encrypted, iv, salt);
    }

    private void validateDeleteInputs(final String id, final String email) {
        if (id == null || id.trim().isEmpty()) {
            throw new InputValidationException("Password ID is required");
        }

        validateEmailInput(email);
    }

    private void validateEmailInput(final String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        if (!SecurityUtil.isValidEmail(email)) {
            throw new InputValidationException("Invalid email format");
        }
    }

    private void validateEncryptionData(final String encrypted, final String iv, final String salt) {
        if (encrypted == null || encrypted.trim().isEmpty()) {
            throw new InputValidationException("Encrypted password data is required");
        }

        if (iv == null || iv.trim().isEmpty()) {
            throw new InputValidationException("Initialization vector is required");
        }

        if (salt == null || salt.trim().isEmpty()) {
            throw new InputValidationException("Salt is required");
        }

        if (!inputSanitizationService.isValidBase64(encrypted) ||
                !inputSanitizationService.isValidBase64(iv) ||
                !inputSanitizationService.isValidBase64(salt)) {
            throw new InputValidationException("Invalid encryption data format");
        }
    }
}