package quest.gekko.wallet.dto.response;

import lombok.Builder;
import lombok.Data;
import quest.gekko.wallet.entity.PasswordEntry;

import java.time.LocalDateTime;

@Data
@Builder
public class PasswordEntryResponse {
    private String id;
    private String name;
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
                .name(entity.getName())
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