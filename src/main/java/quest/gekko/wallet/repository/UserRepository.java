package quest.gekko.wallet.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import quest.gekko.wallet.entity.User;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByEmail(final String email);
}