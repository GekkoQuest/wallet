package quest.gekko.wallet.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "verification_codes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationCode {
    @Id
    private String id;

    @Indexed
    private String email;

    private String code;

    @Indexed(expireAfterSeconds = 0)
    private LocalDateTime expiresAt;

    @Builder.Default
    private int attemptCount = 0;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    private String clientIp;

    public boolean isValid() {
        return expiresAt.isAfter(LocalDateTime.now()) && attemptCount < 5;
    }
}