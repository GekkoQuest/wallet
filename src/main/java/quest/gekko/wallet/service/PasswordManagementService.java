package quest.gekko.wallet.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import quest.gekko.wallet.config.properties.ApplicationProperties;
import quest.gekko.wallet.entity.PasswordEntry;
import quest.gekko.wallet.exception.VaultAccessException;
import quest.gekko.wallet.exception.InputValidationException;
import quest.gekko.wallet.repository.PasswordEntryRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordManagementService {
    private final PasswordEntryRepository passwordEntryRepository;
    private final InputSanitizationService sanitizationService;
    private final SecurityAuditService auditService;
    private final ApplicationProperties appProperties;

    /**
     * Saves a new encrypted password entry
     */
    @Transactional
    public PasswordEntry savePassword(String email, String name, String encrypted, String iv, String salt) {
        validatePasswordInputs(email, name, encrypted, iv, salt);

        long existingCount = passwordEntryRepository.countByEmail(email);

        if (existingCount >= appProperties.getVault().getMaxPasswordsPerUser()) {
            throw new VaultAccessException("Maximum number of passwords reached for this account");
        }

        String sanitizedName = sanitizationService.sanitizePasswordName(name);

        if (sanitizedName == null || sanitizedName.trim().isEmpty()) {
            throw new InputValidationException("Invalid password name provided");
        }

        try {
            PasswordEntry entry = PasswordEntry.builder()
                    .email(email)
                    .name(sanitizedName)
                    .encrypted(encrypted)
                    .iv(iv)
                    .salt(salt)
                    .createdAt(LocalDateTime.now())
                    .accessCount(0)
                    .build();

            PasswordEntry savedEntry = passwordEntryRepository.save(entry);
            log.info("Password entry created for user: {} with name: {}", maskEmail(email), sanitizedName);

            return savedEntry;

        } catch (Exception e) {
            log.error("Failed to save password for user: {}", maskEmail(email), e);
            throw new VaultAccessException("Failed to save password entry", e);
        }
    }

    @Transactional
    public PasswordEntry editPassword(String id, String encrypted, String iv, String salt, String email) {
        // Validate inputs
        validatePasswordInputs(email, "dummy", encrypted, iv, salt);

        if (id == null || id.trim().isEmpty()) {
            throw new InputValidationException("Password ID is required");
        }

        try {
            Optional<PasswordEntry> entryOpt = passwordEntryRepository.findByIdAndEmail(id, email);

            if (entryOpt.isEmpty()) {
                log.warn("Unauthorized password edit attempt by user: {} for ID: {}", maskEmail(email), id);
                throw new SecurityException("Password not found or access denied");
            }

            PasswordEntry entry = entryOpt.get();
            entry.setEncrypted(encrypted);
            entry.setIv(iv);
            entry.setSalt(salt);
            entry.recordModification();

            PasswordEntry savedEntry = passwordEntryRepository.save(entry);
            log.info("Password entry updated for user: {} with ID: {}", maskEmail(email), id);

            return savedEntry;

        } catch (SecurityException e) {
            throw e; // Re-throw security exceptions
        } catch (Exception e) {
            log.error("Failed to edit password for user: {} with ID: {}", maskEmail(email), id, e);
            throw new VaultAccessException("Failed to update password entry", e);
        }
    }

    @Transactional
    public void deletePassword(String id, String email) {
        if (id == null || id.trim().isEmpty()) {
            throw new InputValidationException("Password ID is required");
        }

        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        try {
            Optional<PasswordEntry> entryOpt = passwordEntryRepository.findByIdAndEmail(id, email);

            if (entryOpt.isEmpty()) {
                log.warn("Unauthorized password deletion attempt by user: {} for ID: {}", maskEmail(email), id);
                throw new SecurityException("Password not found or access denied");
            }

            passwordEntryRepository.delete(entryOpt.get());
            log.info("Password entry deleted for user: {} with ID: {}", maskEmail(email), id);

        } catch (SecurityException e) {
            throw e; // Re-throw security exceptions
        } catch (Exception e) {
            log.error("Failed to delete password for user: {} with ID: {}", maskEmail(email), id, e);
            throw new VaultAccessException("Failed to delete password entry", e);
        }
    }

    public List<PasswordEntry> getPasswordsByEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        try {
            List<PasswordEntry> entries = passwordEntryRepository.findByEmailOrderByCreatedAtDesc(email);

            // Update access tracking for retrieved entries
            entries.forEach(entry -> {
                entry.recordAccess();
                passwordEntryRepository.save(entry);
            });

            log.debug("Retrieved {} password entries for user: {}", entries.size(), maskEmail(email));
            return entries;

        } catch (Exception e) {
            log.error("Failed to retrieve passwords for user: {}", maskEmail(email), e);
            throw new VaultAccessException("Failed to load password vault", e);
        }
    }

    public List<PasswordEntry> searchPasswordsByName(String email, String searchPattern) {
        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        if (searchPattern == null || searchPattern.trim().isEmpty()) {
            return getPasswordsByEmail(email);
        }

        try {
            String sanitizedPattern = sanitizationService.sanitizePasswordName(searchPattern);
            List<PasswordEntry> entries = passwordEntryRepository
                    .findByEmailAndNameContainingIgnoreCase(email, sanitizedPattern);

            log.debug("Found {} password entries matching pattern '{}' for user: {}",
                    entries.size(), sanitizedPattern, maskEmail(email));

            return entries;

        } catch (Exception e) {
            log.error("Failed to search passwords for user: {} with pattern: {}",
                    maskEmail(email), searchPattern, e);
            throw new VaultAccessException("Failed to search password vault", e);
        }
    }

    public List<PasswordEntry> getRecentlyAccessedPasswords(String email, int hours) {
        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        try {
            LocalDateTime since = LocalDateTime.now().minusHours(hours);
            List<PasswordEntry> entries = passwordEntryRepository.findRecentlyAccessedByEmail(email, since);

            log.debug("Found {} recently accessed password entries for user: {}",
                    entries.size(), maskEmail(email));

            return entries;

        } catch (Exception e) {
            log.error("Failed to get recently accessed passwords for user: {}", maskEmail(email), e);
            throw new VaultAccessException("Failed to load recent password access", e);
        }
    }

    public VaultStatistics getVaultStatistics(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        try {
            long totalPasswords = passwordEntryRepository.countByEmail(email);
            LocalDateTime past24Hours = LocalDateTime.now().minusHours(24);
            List<PasswordEntry> recentAccess = passwordEntryRepository.findRecentlyAccessedByEmail(email, past24Hours);

            return VaultStatistics.builder()
                    .totalPasswords(totalPasswords)
                    .recentlyAccessedCount(recentAccess.size())
                    .maxPasswordsAllowed(appProperties.getVault().getMaxPasswordsPerUser())
                    .build();

        } catch (Exception e) {
            log.error("Failed to get vault statistics for user: {}", maskEmail(email), e);
            throw new VaultAccessException("Failed to load vault statistics", e);
        }
    }

    private void validatePasswordInputs(String email, String name, String encrypted, String iv, String salt) {
        if (email == null || email.trim().isEmpty()) {
            throw new InputValidationException("User email is required");
        }

        if (!sanitizationService.isValidEmail(email)) {
            throw new InputValidationException("Invalid email format");
        }

        if (name != null && (name.length() > appProperties.getVault().getMaxPasswordNameLength() ||
                !sanitizationService.isValidPasswordName(name))) {
            throw new InputValidationException("Invalid password name");
        }

        if (encrypted == null || encrypted.trim().isEmpty()) {
            throw new InputValidationException("Encrypted password data is required");
        }

        if (iv == null || iv.trim().isEmpty()) {
            throw new InputValidationException("Initialization vector is required");
        }

        if (salt == null || salt.trim().isEmpty()) {
            throw new InputValidationException("Salt is required");
        }

        // Validate base64 format for encrypted data
        if (!isValidBase64(encrypted) || !isValidBase64(iv) || !isValidBase64(salt)) {
            throw new InputValidationException("Invalid encryption data format");
        }
    }

    private boolean isValidBase64(String str) {
        try {
            return str.matches("^[A-Za-z0-9+/]*={0,2}$") && str.length() % 4 == 0;
        } catch (Exception e) {
            return false;
        }
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

    @Builder
    @Data
    public static class VaultStatistics {
        private long totalPasswords;
        private long recentlyAccessedCount;
        private long maxPasswordsAllowed;

        public boolean isNearLimit() {
            return totalPasswords > (maxPasswordsAllowed * 0.8);
        }

        public double getUsagePercentage() {
            return (double) totalPasswords / maxPasswordsAllowed * 100;
        }
    }
}