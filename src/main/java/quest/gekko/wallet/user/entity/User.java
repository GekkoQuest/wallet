package quest.gekko.wallet.user.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    private String id;

    @Indexed(unique = true)
    private String email;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private boolean vaultInitialized = false;

    private LocalDateTime lastLoginAt;

    private String lastLoginIp;

    @Builder.Default
    private boolean accountLocked = false;

    private LocalDateTime lockedUntil;

    @Builder.Default
    private int failedLoginAttempts = 0;

    public boolean isAccountLocked() {
        if (!accountLocked) return false;

        if (lockedUntil != null && LocalDateTime.now().isAfter(lockedUntil)) {
            // Auto-unlock expired locks
            accountLocked = false;
            lockedUntil = null;
            failedLoginAttempts = 0;
            return false;
        }

        return accountLocked;
    }

    public void lockAccount(int lockDurationMinutes) {
        this.accountLocked = true;
        this.lockedUntil = LocalDateTime.now().plusMinutes(lockDurationMinutes);
    }

    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
        this.accountLocked = false;
        this.lockedUntil = null;
    }
}