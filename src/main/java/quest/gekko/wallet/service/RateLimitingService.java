package quest.gekko.wallet.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.config.properties.ApplicationProperties;

import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;
import java.time.Duration;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitingService {
    private final ApplicationProperties applicationProperties;
    private final ConcurrentHashMap<String, AttemptTracker> attemptCache = new ConcurrentHashMap<>();
    private final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();

    public boolean isAllowed(final String identifier, final RateLimitType type) {
        if (identifier == null || type == null) {
            return false;
        }

        final String key = createKey(type, identifier);

        cacheLock.readLock().lock();

        try {
            final AttemptTracker tracker = attemptCache.computeIfAbsent(key, k -> new AttemptTracker());
            final LocalDateTime now = LocalDateTime.now();
            tracker.cleanOldAttempts(now);

            return switch (type) {
                case EMAIL_SEND -> {
                    var limits = applicationProperties.getSecurity().getRateLimit().getEmailSend();
                    yield tracker.getHourlyCount(now) < limits.getPerHour() &&
                            tracker.getMinuteCount(now) < limits.getPerMinute();
                }
                case CODE_VERIFY -> {
                    var limits = applicationProperties.getSecurity().getRateLimit().getCodeVerify();
                    yield tracker.getHourlyCount(now) < limits.getPerHour() &&
                            tracker.getMinuteCount(now) < limits.getPerMinute();
                }
            };
        } finally {
            cacheLock.readLock().unlock();
        }
    }

    public void recordAttempt(final String identifier, final RateLimitType type) {
        if (identifier == null || type == null) {
            return;
        }

        final String key = createKey(type, identifier);

        cacheLock.writeLock().lock();

        try {
            final AttemptTracker tracker = attemptCache.computeIfAbsent(key, k -> new AttemptTracker());
            tracker.addAttempt(LocalDateTime.now());

            log.debug("Recorded {} attempt for identifier: {}", type, maskIdentifier(identifier));
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    @Scheduled(fixedRate = 300000) // Run every 5 minutes
    public void cleanupExpiredEntries() {
        cacheLock.writeLock().lock();

        try {
            final LocalDateTime cutoff = LocalDateTime.now().minus(Duration.ofHours(1));
            final int initialSize = attemptCache.size();

            attemptCache.entrySet().removeIf(entry -> {
                entry.getValue().cleanOldAttempts(LocalDateTime.now());
                return entry.getValue().isEmpty();
            });

            final int finalSize = attemptCache.size();

            if (initialSize > finalSize) {
                log.debug("Cleaned up {} expired rate limit entries", initialSize - finalSize);
            }
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    public int getRemainingAttempts(final String identifier, final RateLimitType type, final Duration window) {
        if (identifier == null || type == null) {
            return 0;
        }

        final String key = createKey(type, identifier);

        cacheLock.readLock().lock();

        try {
            final AttemptTracker tracker = attemptCache.get(key);

            if (tracker == null) {
                return getMaxAttemptsForType(type, window);
            }

            final LocalDateTime now = LocalDateTime.now();
            tracker.cleanOldAttempts(now);

            final int maxAttempts = getMaxAttemptsForType(type, window);
            final int currentAttempts = window.equals(Duration.ofHours(1))
                    ? tracker.getHourlyCount(now)
                    : tracker.getMinuteCount(now);

            return Math.max(0, maxAttempts - currentAttempts);
        } finally {
            cacheLock.readLock().unlock();
        }
    }

    private String createKey(final RateLimitType type, final String identifier) {
        return type.name() + ":" + identifier;
    }

    private String maskIdentifier(final String identifier) {
        if (identifier == null || identifier.length() < 4) {
            return "***";
        }

        return identifier.substring(0, 2) + "***" + identifier.substring(identifier.length() - 2);
    }

    private int getMaxAttemptsForType(final RateLimitType type, final Duration window) {
        return switch (type) {
            case EMAIL_SEND -> {
                var limits = applicationProperties.getSecurity().getRateLimit().getEmailSend();
                yield window.equals(Duration.ofHours(1)) ? limits.getPerHour() : limits.getPerMinute();
            }
            case CODE_VERIFY -> {
                var limits = applicationProperties.getSecurity().getRateLimit().getCodeVerify();
                yield window.equals(Duration.ofHours(1)) ? limits.getPerHour() : limits.getPerMinute();
            }
        };
    }

    public enum RateLimitType {
        EMAIL_SEND,
        CODE_VERIFY
    }

    private static class AttemptTracker {
        private final ConcurrentHashMap<LocalDateTime, Boolean> attempts = new ConcurrentHashMap<>();
        private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

        public void addAttempt(final LocalDateTime time) {
            lock.writeLock().lock();

            try {
                attempts.put(time, Boolean.TRUE);
            } finally {
                lock.writeLock().unlock();
            }
        }

        public void cleanOldAttempts(final LocalDateTime now) {
            lock.writeLock().lock();

            try {
                final LocalDateTime oneHourAgo = now.minus(Duration.ofHours(1));
                attempts.entrySet().removeIf(entry -> entry.getKey().isBefore(oneHourAgo));
            } finally {
                lock.writeLock().unlock();
            }
        }

        public int getHourlyCount(final LocalDateTime now) {
            lock.readLock().lock();

            try {
                final LocalDateTime oneHourAgo = now.minus(Duration.ofHours(1));
                return (int) attempts.keySet().stream()
                        .filter(time -> time.isAfter(oneHourAgo))
                        .count();
            } finally {
                lock.readLock().unlock();
            }
        }

        public int getMinuteCount(final LocalDateTime now) {
            lock.readLock().lock();

            try {
                final LocalDateTime oneMinuteAgo = now.minus(Duration.ofMinutes(1));
                return (int) attempts.keySet().stream()
                        .filter(time -> time.isAfter(oneMinuteAgo))
                        .count();
            } finally {
                lock.readLock().unlock();
            }
        }

        public boolean isEmpty() {
            lock.readLock().lock();

            try {
                return attempts.isEmpty();
            } finally {
                lock.readLock().unlock();
            }
        }
    }
}