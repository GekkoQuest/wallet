package quest.gekko.wallet.vault.dto.response;

import lombok.Builder;
import lombok.Data;
import quest.gekko.wallet.vault.entity.PasswordEntry;

import java.time.LocalDateTime;

@Data
@Builder
public class PasswordEntryResponse {
    private String id;
    private String serviceName;
    private String username;
    private String encrypted;
    private String iv;
    private String salt;

    private LocalDateTime createdAt;
    private LocalDateTime lastModifiedAt;
    private LocalDateTime lastAccessedAt;

    private int accessCount;

    public static PasswordEntryResponse fromEntity(final PasswordEntry entity) {
        return PasswordEntryResponse.builder()
                .id(entity.getId())
                .serviceName(entity.getServiceName())
                .username(entity.getUsername())
                .encrypted(entity.getEncrypted())
                .iv(entity.getIv())
                .salt(entity.getSalt())
                .createdAt(entity.getCreatedAt())
                .lastModifiedAt(entity.getLastModifiedAt())
                .lastAccessedAt(entity.getLastAccessedAt())
                .accessCount(entity.getAccessCount())
                .build();
    }
}