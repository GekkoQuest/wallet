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
import quest.gekko.wallet.util.SecurityUtil;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordManagementService {

    private final PasswordEntryRepository passwordEntryRepository;
    private final InputSanitizationService inputSanitizationService;
    private final SecurityAuditService securityAuditService;
    private final ApplicationProperties applicationProperties;

    @Transactional
    public void savePassword(final String email, final String name, final String encrypted, final String iv, final String salt) {
        validatePasswordInputs(email, name, encrypted, iv, salt);

        final long existingCount = passwordEntryRepository.countByEmail(email);

        if (existingCount >= applicationProperties.getVault().getMaxPasswordsPerUser()) {
            throw new VaultAccessException("Maximum number of passwords reached for this account");
        }

        final String sanitizedName = inputSanitizationService.sanitizePasswordName(name);

        if (sanitizedName == null || sanitizedName.trim().isEmpty()) {
            throw new InputValidationException("Invalid password name provided");
        }

        try {
            final PasswordEntry entry = PasswordEntry.builder()
                    .email(email)
                    .name(sanitizedName)
                    .encrypted(encrypted)
                    .iv(iv)
                    .salt(salt)
                    .createdAt(LocalDateTime.now())
                    .accessCount(0)
                    .build();

            passwordEntryRepository.save(entry);
            log.info("Password entry created for user: {} with name: {}", SecurityUtil.maskEmail(email), sanitizedName);
        } catch (final Exception e) {
            log.error("Failed to save password for user: {}", SecurityUtil.maskEmail(email), e);
            throw new VaultAccessException("Failed to save password entry", e);
        }
    }

    @Transactional
    public void editPassword(String id, String encrypted, String iv, String salt, String email) {
        validateEditInputs(id, encrypted, iv, salt, email);

        try {
            final Optional<PasswordEntry> entryOpt = passwordEntryRepository.findByIdAndEmail(id, email);

            if (entryOpt.isEmpty()) {
                log.warn("Unauthorized password edit attempt by user: {} for ID: {}", SecurityUtil.maskEmail(email), id);
                throw new SecurityException("Password not found or access denied");
            }

            final PasswordEntry entry = entryOpt.get();
            entry.setEncrypted(encrypted);
            entry.setIv(iv);
            entry.setSalt(salt);
            entry.recordModification();

            passwordEntryRepository.save(entry);
            log.info("Password entry updated for user: {} with ID: {}", SecurityUtil.maskEmail(email), id);
        } catch (SecurityException e) {
            throw e; // Re-throw security exceptions
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
                throw new SecurityException("Password not found or access denied");
            }

            passwordEntryRepository.delete(entryOpt.get());
            log.info("Password entry deleted for user: {} with ID: {}",
                    SecurityUtil.maskEmail(email), id);

        } catch (final SecurityException e) {
            throw e; // Re-throw security exceptions
        } catch (final Exception e) {
            log.error("Failed to delete password for user: {} with ID: {}", SecurityUtil.maskEmail(email), id, e);
            throw new VaultAccessException("Failed to delete password entry", e);
        }
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

            if (sanitizedPattern == null) {
                return getPasswordsByEmail(email);
            }

            final List<PasswordEntry> entries = passwordEntryRepository.findByEmailAndNameContainingIgnoreCase(email, sanitizedPattern);

            log.debug("Found {} password entries matching pattern '{}' for user: {}", entries.size(), sanitizedPattern, SecurityUtil.maskEmail(email));
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
            log.debug("Found {} recently accessed password entries for user: {}", entries.size(), SecurityUtil.maskEmail(email));
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
                log.debug("Recorded access for password ID: {} by user: {}", passwordId, SecurityUtil.maskEmail(email));
            }
        } catch (final Exception e) {
            log.warn("Failed to record password access for user: {} and ID: {}", SecurityUtil.maskEmail(email), passwordId, e);
            // Don't throw exception here as it's not critical for the main operation
        }
    }

    @Transactional(readOnly = true)
    public VaultStatistics getVaultStatistics(final String email) {
        validateEmailInput(email);

        try {
            final long totalPasswords = passwordEntryRepository.countByEmail(email);
            final LocalDateTime past24Hours = LocalDateTime.now().minusHours(24);
            final List<PasswordEntry> recentAccess = passwordEntryRepository.findRecentlyAccessedByEmail(email, past24Hours);

            return VaultStatistics.builder()
                    .totalPasswords(totalPasswords)
                    .recentlyAccessedCount(recentAccess.size())
                    .maxPasswordsAllowed(applicationProperties.getVault().getMaxPasswordsPerUser())
                    .build();
        } catch (final Exception e) {
            log.error("Failed to get vault statistics for user: {}", SecurityUtil.maskEmail(email), e);
            throw new VaultAccessException("Failed to load vault statistics", e);
        }
    }

    private void validatePasswordInputs(final String email, final String name, final String encrypted, final String iv, final String salt) {
        validateEmailInput(email);

        if (name == null || name.trim().isEmpty()) {
            throw new InputValidationException("Password name is required");
        }

        if (name.length() > applicationProperties.getVault().getMaxPasswordNameLength()) {
            throw new InputValidationException("Password name is too long");
        }

        if (!inputSanitizationService.isValidPasswordName(name)) {
            throw new InputValidationException("Invalid password name format");
        }

        validateEncryptionData(encrypted, iv, salt);
    }

    private void validateEditInputs(final String id, final String encrypted, final String iv, final String salt, final String email) {
        if (id == null || id.trim().isEmpty()) {
            throw new InputValidationException("Password ID is required");
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
            return maxPasswordsAllowed > 0 ? (double) totalPasswords / maxPasswordsAllowed * 100 : 0;
        }
    }
}