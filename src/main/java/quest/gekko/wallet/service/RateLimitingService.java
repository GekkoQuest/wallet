package quest.gekko.wallet.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.config.properties.ApplicationProperties;

import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;
import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitingService {

    private final ApplicationProperties appProperties;
    private final ConcurrentHashMap<String, AttemptInfo> attemptCache = new ConcurrentHashMap<>();

    public boolean isAllowed(String identifier, RateLimitType type) {
        String key = type.name() + ":" + identifier;
        AttemptInfo info = attemptCache.computeIfAbsent(key, k -> new AttemptInfo());

        LocalDateTime now = LocalDateTime.now();

        info.cleanOldAttempts(now);

        // Check limits based on type
        return switch (type) {
            case EMAIL_SEND -> {
                var limits = appProperties.getSecurity().getRateLimit().getEmailSend();
                yield info.getHourlyCount() < limits.getPerHour() &&
                        info.getMinuteCount() < limits.getPerMinute();
            }
            case CODE_VERIFY -> {
                var limits = appProperties.getSecurity().getRateLimit().getCodeVerify();
                yield info.getHourlyCount() < limits.getPerHour() &&
                        info.getMinuteCount() < limits.getPerMinute();
            }
        };
    }

    public void recordAttempt(String identifier, RateLimitType type) {
        String key = type.name() + ":" + identifier;
        AttemptInfo info = attemptCache.computeIfAbsent(key, k -> new AttemptInfo());
        info.addAttempt(LocalDateTime.now());

        log.debug("Recorded {} attempt for {}", type, identifier);
    }

    public enum RateLimitType {
        EMAIL_SEND, CODE_VERIFY
    }

    private static class AttemptInfo {
        private final ConcurrentHashMap<LocalDateTime, Boolean> attempts = new ConcurrentHashMap<>();

        public void addAttempt(LocalDateTime time) {
            attempts.put(time, true);
        }

        public void cleanOldAttempts(LocalDateTime now) {
            LocalDateTime oneHourAgo = now.minus(Duration.ofHours(1));
            attempts.entrySet().removeIf(entry -> entry.getKey().isBefore(oneHourAgo));
        }

        public int getHourlyCount() {
            LocalDateTime oneHourAgo = LocalDateTime.now().minus(Duration.ofHours(1));
            return (int) attempts.keySet().stream()
                    .filter(time -> time.isAfter(oneHourAgo))
                    .count();
        }

        public int getMinuteCount() {
            LocalDateTime oneMinuteAgo = LocalDateTime.now().minus(Duration.ofMinutes(1));
            return (int) attempts.keySet().stream()
                    .filter(time -> time.isAfter(oneMinuteAgo))
                    .count();
        }
    }
}