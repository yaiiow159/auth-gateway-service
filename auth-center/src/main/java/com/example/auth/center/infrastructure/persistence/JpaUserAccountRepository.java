package com.example.auth.center.infrastructure.persistence;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.port.UserAccountRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** {@link UserAccountRepository} 的 JPA Adapter。 */
@Repository
@Transactional(readOnly = true)
public class JpaUserAccountRepository implements UserAccountRepository {

    private final UserJpaRepository jpaRepository;

    public JpaUserAccountRepository(UserJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        return jpaRepository.findByUsernameWithAuthorities(username).map(UserAccountMapper::toDomain);
    }

    @Override
    public Optional<UserAccount> findById(UserId userId) {
        return jpaRepository.findByIdWithAuthorities(userId.value()).map(UserAccountMapper::toDomain);
    }
}
