package quest.gekko.wallet.vault.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import quest.gekko.wallet.user.entity.User;
import quest.gekko.wallet.user.repository.UserRepository;
import quest.gekko.wallet.vault.entity.PasswordEntry;
import quest.gekko.wallet.vault.repository.PasswordEntryRepository;
import quest.gekko.wallet.authentication.service.EmailService;
import quest.gekko.wallet.audit.service.SecurityAuditService;
import quest.gekko.wallet.security.util.SecurityUtil;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccountDeletionService {
    private final UserRepository userRepository;
    private final PasswordEntryRepository passwordEntryRepository;
    private final EmailService emailService;
    private final SecurityAuditService securityAuditService;

    @Transactional
    public boolean deleteAccount(final String email, final String clientIp) {
        try {
            if (email == null || email.trim().isEmpty()) {
                throw new SecurityException("Email is required");
            }

            final Optional<User> userOpt = userRepository.findByEmail(email);

            if (userOpt.isEmpty()) {
                log.warn("Account deletion attempted for non-existent user: {}", SecurityUtil.maskEmail(email));
                return false;
            }

            final User user = userOpt.get();

            final long passwordCount = passwordEntryRepository.countByEmail(email);

            final List<PasswordEntry> userPasswords = passwordEntryRepository.findByEmail(email);
            passwordEntryRepository.deleteAll(userPasswords);

            userRepository.delete(user);

            sendAccountDeletionEmail(email, passwordCount, clientIp);

            log.warn("Account successfully deleted for user: {} - {} passwords removed, from IP: {}",
                    SecurityUtil.maskEmail(email), passwordCount, clientIp);

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    String.format("Account deleted successfully - %d passwords removed", passwordCount),
                    clientIp
            );
            return true;
        } catch (final SecurityException e) {
            log.warn("Security violation during account deletion for user: {}: {}", SecurityUtil.maskEmail(email), e.getMessage());
            throw e;
        } catch (final Exception e) {
            log.error("Failed to delete account for user: {} from IP: {}", SecurityUtil.maskEmail(email), clientIp, e);
            throw new RuntimeException("Account deletion failed", e);
        }
    }

    private void sendAccountDeletionEmail(final String email, final long deletedPasswordCount, final String clientIp) {
        try {
            emailService.sendSecurityAlert(
                    email,
                    "Account Permanently Deleted",
                    String.format("Your Wallet account has been permanently deleted as requested. " +
                                    "%d password entries were removed. " +
                                    "This action was performed from IP address %s. " +
                                    "Thank you for using our demo service. " +
                                    "If this was not you, please contact support immediately as someone may have had unauthorized access to your account.",
                            deletedPasswordCount, clientIp),
                    clientIp
            );

            log.info("Account deletion notification email sent to: {}", SecurityUtil.maskEmail(email));
        } catch (final Exception e) {
            log.warn("Failed to send account deletion email to: {}", SecurityUtil.maskEmail(email), e);
        }
    }
}