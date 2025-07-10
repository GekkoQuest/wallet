package quest.gekko.wallet.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import quest.gekko.wallet.config.properties.ApplicationProperties;
import quest.gekko.wallet.entity.User;
import quest.gekko.wallet.entity.VerificationCode;
import quest.gekko.wallet.exception.AuthenticationException;
import quest.gekko.wallet.exception.RateLimitExceededException;
import quest.gekko.wallet.repository.UserRepository;
import quest.gekko.wallet.repository.VerificationCodeRepository;

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

    private final SecureRandom secureRandom = new SecureRandom();

    public void sendVerificationCode(String email, String clientIp) {
        // Generate 6-digit code
        String code = String.format("%06d", secureRandom.nextInt(1000000));

        // Create verification code
        VerificationCode verificationCode = VerificationCode.builder()
                .email(email)
                .code(code)
                .expiresAt(LocalDateTime.now().plusMinutes(10))
                .attemptCount(0)
                .createdAt(LocalDateTime.now())
                .clientIp(clientIp)
                .build();

        // Remove old codes and save new one
        verificationCodeRepository.deleteByEmail(email);
        verificationCodeRepository.save(verificationCode);

        // Send email
        emailService.sendVerificationCode(email, code);

        log.info("Verification code sent to: {}", maskEmail(email));
    }

    public Optional<User> verifyCodeAndAuthenticate(String email, String code, String clientIp) {
        // Locate verification code
        Optional<VerificationCode> verificationCodeOpt = verificationCodeRepository.findByEmailAndCode(email, code);

        if (verificationCodeOpt.isEmpty()) {
            log.warn("Invalid verification code for: {}", maskEmail(email));
            return Optional.empty();
        }

        VerificationCode verificationCode = verificationCodeOpt.get();

        // Check if expired
        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Expired verification code for: {}", maskEmail(email));
            verificationCodeRepository.delete(verificationCode);
            return Optional.empty();
        }

        // Code is valid - remove it
        verificationCodeRepository.delete(verificationCode);

        // Find or create user
        Optional<User> existingUser = userRepository.findByEmail(email);

        User user;
        if (existingUser.isPresent()) {
            user = existingUser.get();
            user.setLastLoginAt(LocalDateTime.now());
            user.setLastLoginIp(clientIp);
            user = userRepository.save(user);
            log.info("User logged in: {}", maskEmail(email));
        } else {
            user = User.builder()
                    .email(email)
                    .createdAt(LocalDateTime.now())
                    .lastLoginAt(LocalDateTime.now())
                    .lastLoginIp(clientIp)
                    .vaultInitialized(false)
                    .build();
            user = userRepository.save(user);
            log.info("New user created: {}", maskEmail(email));
        }

        return Optional.of(user);
    }

    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        int atIndex = email.indexOf('@');
        if (atIndex <= 0) return "***";
        String username = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        if (username.length() <= 2) {
            return "*".repeat(username.length()) + domain;
        }
        return username.charAt(0) + "*".repeat(username.length() - 2) + username.charAt(username.length() - 1) + domain;
    }
}