package quest.gekko.wallet.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import quest.gekko.wallet.common.config.properties.ApplicationProperties;
import quest.gekko.wallet.user.entity.User;
import quest.gekko.wallet.authentication.entity.VerificationCode;
import quest.gekko.wallet.common.exception.RateLimitExceededException;
import quest.gekko.wallet.user.repository.UserRepository;
import quest.gekko.wallet.authentication.repository.VerificationCodeRepository;
import quest.gekko.wallet.common.email.service.EmailService;
import quest.gekko.wallet.security.ratelimit.service.RateLimitingService;
import quest.gekko.wallet.security.audit.service.SecurityAuditService;
import quest.gekko.wallet.security.util.SecurityUtil;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final UserRepository userRepository;
    private final VerificationCodeRepository verificationCodeRepository;

    private final EmailService emailService;
    private final RateLimitingService rateLimitingService;
    private final SecurityAuditService securityAuditService;
    private final ApplicationProperties applicationProperties;

    private final SecureRandom secureRandom = new SecureRandom();

    public void sendVerificationCode(final String email, final String clientIp) {
        validateRateLimit(email, clientIp, RateLimitingService.RateLimitType.EMAIL_SEND);

        final String verificationCode = generateSecureVerificationCode();

        cleanupExpiredCodes();
        verificationCodeRepository.deleteByEmail(email);

        final VerificationCode code = createVerificationCode(email, verificationCode, clientIp);
        verificationCodeRepository.save(code);

        emailService.sendVerificationCode(email, verificationCode);
        rateLimitingService.recordAttempt(email + ":" + clientIp, RateLimitingService.RateLimitType.EMAIL_SEND);

        securityAuditService.logSecurityEvent(
                SecurityAuditService.SecurityEventType.SUCCESSFUL_AUTHENTICATION,
                email,
                "Verification code sent",
                clientIp
        );

        log.info("Verification code sent to: {}", SecurityUtil.maskEmail(email));
    }

    @Transactional
    public Optional<User> verifyCodeAndAuthenticate(final String email, final String code, final String clientIp) {
        validateRateLimit(email, clientIp, RateLimitingService.RateLimitType.CODE_VERIFY);

        final Optional<VerificationCode> verificationCodeOpt = findAndValidateCode(email, code);

        if (verificationCodeOpt.isEmpty()) {
            handleFailedVerification(email, clientIp, "Invalid verification code");
            return Optional.empty();
        }

        final VerificationCode verificationCode = verificationCodeOpt.get();

        if (isCodeExpired(verificationCode)) {
            verificationCodeRepository.delete(verificationCode);
            handleFailedVerification(email, clientIp, "Expired verification code");
            return Optional.empty();
        }

        if (hasExceededAttempts(verificationCode)) {
            verificationCodeRepository.delete(verificationCode);
            handleFailedVerification(email, clientIp, "Too many verification attempts");
            return Optional.empty();
        }

        verificationCodeRepository.delete(verificationCode);
        rateLimitingService.recordAttempt(email + ":" + clientIp, RateLimitingService.RateLimitType.CODE_VERIFY);

        return findOrCreateUser(email, clientIp);
    }

    @Scheduled(fixedRate = 300000)
    @Transactional
    public void cleanupExpiredCodes() {
        final long deletedCount = verificationCodeRepository.countByExpiresAtBefore(LocalDateTime.now());
        verificationCodeRepository.deleteByExpiresAtBefore(LocalDateTime.now());

        if (deletedCount > 0) {
            log.debug("Cleaned up {} expired verification codes", deletedCount);
        }
    }

    private void validateRateLimit(final String email, final String clientIp, final RateLimitingService.RateLimitType type) {
        final String identifier = email + ":" +  clientIp;

        if (!rateLimitingService.isAllowed(identifier, type)) {
            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.RATE_LIMIT_EXCEEDED,
                    email,
                    "Rate limit exceeded for " + type,
                    clientIp
            );

            throw new RateLimitExceededException("Rate limit exceeded. Please try again later.");
        }
    }

    private String generateSecureVerificationCode() {
        final int codeLength = applicationProperties.getVerification().getCode().getLength();
        final int maxValue = (int) Math.pow(10, codeLength) - 1;
        final int code = secureRandom.nextInt(maxValue + 1);
        return String.format("%0" + codeLength + "d", code);
    }

    private VerificationCode createVerificationCode(final String email, final String code, final String clientIp) {
        final int expiryMinutes = applicationProperties.getVerification().getCode().getExpiry().getMinutes();

        return VerificationCode.builder()
                .email(email)
                .code(code)
                .expiresAt(LocalDateTime.now().plusMinutes(expiryMinutes))
                .attemptCount(0)
                .createdAt(LocalDateTime.now())
                .clientIp(clientIp)
                .build();
    }

    private Optional<VerificationCode> findAndValidateCode(final String email, final String code) {
        return verificationCodeRepository.findByEmailAndCode(email, code);
    }

    private boolean isCodeExpired(final VerificationCode verificationCode) {
        return verificationCode.getExpiresAt().isBefore(LocalDateTime.now());
    }

    private boolean hasExceededAttempts(final VerificationCode verificationCode) {
        final int maxAttempts = applicationProperties.getVerification().getMaxAttempts();
        return verificationCode.getAttemptCount() >= maxAttempts;
    }

    private void handleFailedVerification(final String email, final String clientIp, final String reason) {
        securityAuditService.logFailedAuthentication(email, clientIp, reason);
        log.warn("Authentication failed for {}: {}", SecurityUtil.maskEmail(email), reason);
    }

    private Optional<User> findOrCreateUser(final String email, final String clientIp) {
        final Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            updateUserLoginInfo(user, clientIp);
            user = userRepository.save(user);

            securityAuditService.logSuccessfulAuthentication(email, clientIp);
            log.info("User logged in: {}", SecurityUtil.maskEmail(email));
            return Optional.of(user);
        } else {
            final User user = createNewUser(email, clientIp);
            final User savedUser = userRepository.save(user);

            securityAuditService.logSuccessfulAuthentication(email, clientIp);
            log.info("New user created: {}", SecurityUtil.maskEmail(email));
            return Optional.of(savedUser);
        }
    }

    private void updateUserLoginInfo(final User user, final String clientIp) {
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(clientIp);
        user.resetFailedAttempts();
    }

    private User createNewUser(final String email, final String clientIp) {
        return User.builder()
                .email(email)
                .createdAt(LocalDateTime.now())
                .lastLoginAt(LocalDateTime.now())
                .lastLoginIp(clientIp)
                .vaultInitialized(false)
                .build();
    }
}