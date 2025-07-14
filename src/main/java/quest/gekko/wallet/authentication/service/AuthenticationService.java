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
import quest.gekko.wallet.ratelimit.service.RateLimitingService;
import quest.gekko.wallet.audit.service.SecurityAuditService;
import quest.gekko.wallet.security.util.SecurityUtil;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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

    private final ConcurrentHashMap<String, Integer> failedVerificationAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LocalDateTime> lastFailedAttempt = new ConcurrentHashMap<>();
    private static final int MAX_FAILED_VERIFICATION_ATTEMPTS = 5;
    private static final int VERIFICATION_ATTEMPT_WINDOW_MINUTES = 30;

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

            emailService.sendSecurityAlert(
                    email,
                    "Too Many Verification Attempts",
                    String.format("Multiple failed verification code attempts detected from IP address %s. " +
                            "If this wasn't you, someone may be trying to access your account.", clientIp),
                    clientIp
            );

            return Optional.empty();
        }

        checkSuspiciousVerificationActivity(email, clientIp);

        verificationCodeRepository.delete(verificationCode);
        rateLimitingService.recordAttempt(email + ":" + clientIp, RateLimitingService.RateLimitType.CODE_VERIFY);

        final String attemptKey = email + ":" + clientIp;
        failedVerificationAttempts.remove(attemptKey);
        lastFailedAttempt.remove(attemptKey);

        return findOrCreateUser(email, clientIp);
    }

    @Scheduled(fixedRate = 300000)
    public void cleanupExpiredCodes() {
        final long deletedCount = verificationCodeRepository.countByExpiresAtBefore(LocalDateTime.now());
        verificationCodeRepository.deleteByExpiresAtBefore(LocalDateTime.now());

        if (deletedCount > 0) {
            log.debug("Cleaned up {} expired verification codes", deletedCount);
        }

        cleanupOldFailedAttempts();
    }

    private void cleanupOldFailedAttempts() {
        final LocalDateTime cutoff = LocalDateTime.now().minusMinutes(VERIFICATION_ATTEMPT_WINDOW_MINUTES);

        lastFailedAttempt.entrySet().removeIf(entry -> {
            if (entry.getValue().isBefore(cutoff)) {
                failedVerificationAttempts.remove(entry.getKey());
                return true;
            }
            return false;
        });
    }

    private void checkSuspiciousVerificationActivity(final String email, final String clientIp) {
        final String attemptKey = email + ":" + clientIp;
        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime windowStart = now.minusMinutes(VERIFICATION_ATTEMPT_WINDOW_MINUTES);

        final LocalDateTime lastAttempt = lastFailedAttempt.get(attemptKey);
        if (lastAttempt != null && lastAttempt.isBefore(windowStart)) {
            failedVerificationAttempts.remove(attemptKey);
            lastFailedAttempt.remove(attemptKey);
            return;
        }

        final int attempts = failedVerificationAttempts.getOrDefault(attemptKey, 0);

        if (attempts >= 3) {
            emailService.sendSecurityAlert(
                    email,
                    "Multiple Failed Verification Attempts Before Success",
                    String.format("There were %d failed verification attempts from IP address %s before a successful login. " +
                            "If this wasn't you, someone may have been trying to access your account.", attempts, clientIp),
                    clientIp
            );

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    String.format("Multiple failed verification attempts (%d) before success", attempts),
                    clientIp
            );
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

            emailService.sendSecurityAlert(
                    email,
                    "Rate Limit Exceeded",
                    String.format("Too many %s requests detected from IP address %s. " +
                                    "If this wasn't you, someone may be trying to access your account repeatedly.",
                            type == RateLimitingService.RateLimitType.EMAIL_SEND ? "login code" : "verification",
                            clientIp),
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

        final String attemptKey = email + ":" + clientIp;
        final LocalDateTime now = LocalDateTime.now();
        final LocalDateTime windowStart = now.minusMinutes(VERIFICATION_ATTEMPT_WINDOW_MINUTES);

        final LocalDateTime lastAttempt = lastFailedAttempt.get(attemptKey);
        if (lastAttempt != null && lastAttempt.isBefore(windowStart)) {
            failedVerificationAttempts.remove(attemptKey);
            lastFailedAttempt.remove(attemptKey);
        }

        final int attempts = failedVerificationAttempts.merge(attemptKey, 1, Integer::sum);
        lastFailedAttempt.put(attemptKey, now);

        log.warn("Failed verification attempt #{} for user: {} from IP: {}", attempts, SecurityUtil.maskEmail(email), clientIp);

        if (attempts >= MAX_FAILED_VERIFICATION_ATTEMPTS) {
            emailService.sendSecurityAlert(
                    email,
                    "Multiple Failed Verification Attempts",
                    String.format("We detected %d failed verification attempts in the last %d minutes from IP address %s. " +
                                    "If this wasn't you, your account may be under attack. " +
                                    "Consider using a different device or network if you suspect malicious activity.",
                            attempts, VERIFICATION_ATTEMPT_WINDOW_MINUTES, clientIp),
                    clientIp
            );

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    email,
                    String.format("Too many failed verification attempts: %d in %d minutes", attempts, VERIFICATION_ATTEMPT_WINDOW_MINUTES),
                    clientIp
            );
        }
    }

    private Optional<User> findOrCreateUser(final String email, final String clientIp) {
        final Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();

            checkSuspiciousLoginActivity(user, clientIp);

            updateUserLoginInfo(user, clientIp);
            user = userRepository.save(user);

            securityAuditService.logSuccessfulAuthentication(email, clientIp);
            log.info("User logged in: {}", SecurityUtil.maskEmail(email));
            return Optional.of(user);
        } else {
            final User user = createNewUser(email, clientIp);
            final User savedUser = userRepository.save(user);

            emailService.sendSecurityAlert(
                    email,
                    "New Account Created",
                    String.format("Welcome to %s! Your account was just created from IP address %s. " +
                                    "If you didn't create this account, please contact support immediately.",
                            applicationProperties.getName(), clientIp),
                    clientIp
            );

            securityAuditService.logSuccessfulAuthentication(email, clientIp);
            log.info("New user created: {}", SecurityUtil.maskEmail(email));
            return Optional.of(savedUser);
        }
    }

    private void checkSuspiciousLoginActivity(final User user, final String clientIp) {
        if (user.getLastLoginIp() != null && !user.getLastLoginIp().equals(clientIp)) {
            emailService.sendSecurityAlert(
                    user.getEmail(),
                    "Login from New Location",
                    String.format("Your account was accessed from a new IP address: %s. " +
                                    "Previous login was from: %s. " +
                                    "If this wasn't you, please secure your account immediately.",
                            clientIp, user.getLastLoginIp()),
                    clientIp
            );

            securityAuditService.logSecurityEvent(
                    SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                    user.getEmail(),
                    String.format("Login from new IP. Previous: %s, Current: %s", user.getLastLoginIp(), clientIp),
                    clientIp
            );
        }

        if (user.getLastLoginAt() != null) {
            final LocalDateTime fiveMinutesAgo = LocalDateTime.now().minusMinutes(5);
            if (user.getLastLoginAt().isAfter(fiveMinutesAgo)) {
                log.warn("Rapid successive login detected for user: {} from IP: {}",
                        SecurityUtil.maskEmail(user.getEmail()), clientIp);

                securityAuditService.logSecurityEvent(
                        SecurityAuditService.SecurityEventType.SUSPICIOUS_ACTIVITY,
                        user.getEmail(),
                        "Rapid successive login detected",
                        clientIp
                );
            }
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