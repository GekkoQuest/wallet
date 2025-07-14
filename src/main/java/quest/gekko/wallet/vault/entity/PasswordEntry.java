package quest.gekko.wallet.vault.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "password_entries")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordEntry {
    @Id
    private String id;

    @Indexed
    private String email;

    private String serviceName;
    private String username;

    private String encrypted;
    private String iv;
    private String salt;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime lastModifiedAt;
    private LocalDateTime lastAccessedAt;

    @Builder.Default
    private int accessCount = 0;

    public void recordAccess() {
        this.lastAccessedAt = LocalDateTime.now();
        this.accessCount++;
    }

    public void recordModification() {
        this.lastModifiedAt = LocalDateTime.now();
    }
}