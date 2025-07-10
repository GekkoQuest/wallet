package quest.gekko.wallet.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import quest.gekko.wallet.entity.PasswordEntry;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface PasswordEntryRepository extends MongoRepository<PasswordEntry, String> {

    List<PasswordEntry> findByEmailOrderByCreatedAtDesc(String email);

    Optional<PasswordEntry> findByIdAndEmail(String id, String email);

    long countByEmail(String email);

    List<PasswordEntry> findByEmail(String email);

    @Query("{ 'email': ?0, 'lastAccessedAt': { $gte: ?1 } }")
    List<PasswordEntry> findRecentlyAccessedByEmail(String email, LocalDateTime since);

    @Query("{ 'email': ?0, 'name': { $regex: ?1, $options: 'i' } }")
    List<PasswordEntry> findByEmailAndNameContainingIgnoreCase(String email, String namePattern);

    void deleteByEmailAndId(String email, String id);
}