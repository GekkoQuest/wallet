package quest.gekko.wallet.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import quest.gekko.wallet.entity.VerificationCode;

import java.time.LocalDateTime;
import java.util.Optional;

public interface VerificationCodeRepository extends MongoRepository<VerificationCode, String> {

    Optional<VerificationCode> findByEmailAndCode(String email, String code);

    void deleteByEmail(String email);

    void deleteByExpiresAtBefore(LocalDateTime dateTime);

    long countByExpiresAtBefore(LocalDateTime dateTime);

    @Query("{ 'email': ?0, 'createdAt': { $gte: ?1 } }")
    long countByEmailAndCreatedAtAfter(String email, LocalDateTime since);

    Optional<VerificationCode> findByEmail(String email);
}