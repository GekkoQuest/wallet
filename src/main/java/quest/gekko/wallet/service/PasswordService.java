package quest.gekko.wallet.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.entity.PasswordEntry;
import quest.gekko.wallet.repository.PasswordEntryRepository;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class PasswordService {
    private final PasswordEntryRepository passwordEntryRepository;

    public void savePassword(final String email, final String name, final String encrypted, final String iv, final String salt) {
        final PasswordEntry entry = PasswordEntry.builder()
                .email(email)
                .name(name)
                .encrypted(encrypted)
                .iv(iv)
                .salt(salt)
                .createdAt(LocalDateTime.now())
                .build();
        passwordEntryRepository.save(entry);
    }

    public void editPassword(final String id, final String encrypted, final String iv, final String salt, final String email) {
        PasswordEntry entry = passwordEntryRepository.findByIdAndEmail(id, email)
                .orElseThrow(() -> new RuntimeException("Not authorized"));

        entry.setEncrypted(encrypted);
        entry.setIv(iv);
        entry.setSalt(salt);
        entry.recordModification();
        passwordEntryRepository.save(entry);
    }

    public void deletePassword(String id, String email) {
        PasswordEntry entry = passwordEntryRepository.findByIdAndEmail(id, email)
                .orElseThrow(() -> new RuntimeException("Not authorized"));

        passwordEntryRepository.delete(entry);
    }

    public List<PasswordEntry> getPasswordsByEmail(final String email) {
        return passwordEntryRepository.findByEmailOrderByCreatedAtDesc(email);
    }
}