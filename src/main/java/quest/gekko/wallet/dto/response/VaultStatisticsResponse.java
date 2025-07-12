package quest.gekko.wallet.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VaultStatisticsResponse {
    private long totalPasswords;
    private long recentlyAccessedCount;
    private long maxPasswordsAllowed;

    private double usagePercentage;

    private boolean nearLimit;

    public static VaultStatisticsResponse fromStatistics(final long totalPasswords, final long recentlyAccessedCount, final long maxPasswordsAllowed) {
        final double usagePercentage = maxPasswordsAllowed > 0 ? (double) totalPasswords / maxPasswordsAllowed * 100 : 0;
        final boolean nearLimit = totalPasswords > (maxPasswordsAllowed * 0.8);

        return VaultStatisticsResponse.builder()
                .totalPasswords(totalPasswords)
                .recentlyAccessedCount(recentlyAccessedCount)
                .maxPasswordsAllowed(maxPasswordsAllowed)
                .usagePercentage(usagePercentage)
                .nearLimit(nearLimit)
                .build();
    }
}