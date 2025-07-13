package quest.gekko.wallet.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.vault.entity.PasswordEntry;
import quest.gekko.wallet.vault.repository.PasswordEntryRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AgedPasswordService {
    private final PasswordEntryRepository passwordEntryRepository;

    // Calling it "Aged" as I do not wish for anyone to get confused with it being called "Old" and thinking it's a soon-to-be deprecated service
    public List<PasswordEntry> getAgedPasswords(final String email) {
        final LocalDateTime sixMonthsAgo = LocalDateTime.now().minusMonths(6);
        final LocalDateTime threeMonthsAgo = LocalDateTime.now().minusMonths(3);

        return passwordEntryRepository.findByEmail(email).stream()
                .filter(entry -> entry.getCreatedAt().isBefore(sixMonthsAgo) &&
                        (entry.getLastModifiedAt() == null || entry.getLastModifiedAt().isBefore(threeMonthsAgo)))
                .collect(Collectors.toList());
    }

    public int getAgedPasswordCount(final String email) {
        return getAgedPasswords(email).size();
    }
}
