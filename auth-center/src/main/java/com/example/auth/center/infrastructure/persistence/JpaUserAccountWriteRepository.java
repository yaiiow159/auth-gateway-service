package com.example.auth.center.infrastructure.persistence;

import com.example.auth.center.domain.model.AccountStatus;
import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.port.UserAccountWriteRepository;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** {@link UserAccountWriteRepository} 的 JPA Adapter。 */
@Repository
@Transactional
public class JpaUserAccountWriteRepository implements UserAccountWriteRepository {

    private final UserJpaRepository userRepository;
    private final RoleJpaRepository roleRepository;

    public JpaUserAccountWriteRepository(UserJpaRepository userRepository, RoleJpaRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByUsername(String username) {
        return userRepository.findByUsernameWithAuthorities(username).isPresent();
    }

    @Override
    public UserAccount create(UserId id, String username, String passwordHash,
                              String tenantId, Set<String> roleCodes) {
        UserEntity entity = new UserEntity(
                id.value(), username, passwordHash, tenantId, AccountStatus.ACTIVE);
        entity.replaceRoles(resolveRoles(roleCodes));
        return UserAccountMapper.toDomain(userRepository.save(entity));
    }

    @Override
    public void updatePasswordHash(UserId userId, String passwordHash) {
        require(userId).changePasswordHash(passwordHash);
    }

    @Override
    public void updateStatus(UserId userId, AccountStatus status) {
        require(userId).changeStatus(status);
    }

    @Override
    public void replaceRoles(UserId userId, Set<String> roleCodes) {
        require(userId).replaceRoles(resolveRoles(roleCodes));
    }

    /**
     * 在交易內取出受管理的 Entity，後續的修改由 JPA 的 dirty checking 自動寫回，
     * 因此不需要顯式呼叫 save。
     */
    private UserEntity require(UserId userId) {
        return userRepository.findById(userId.value())
                .orElseThrow(() -> new UserNotFoundException(userId.value()));
    }

    /**
     * 解析角色代碼。
     *
     * <p>任何一個代碼查不到就整批失敗：若靜默略過，管理者會得到一個
     * 「建立成功但少了權限」的帳號，而問題要等到使用者反應存取被拒才會浮現。
     */
    private Set<RoleEntity> resolveRoles(Set<String> roleCodes) {
        if (roleCodes.isEmpty()) {
            return Set.of();
        }
        List<RoleEntity> found = roleRepository.findByCodeIn(roleCodes);
        if (found.size() != roleCodes.size()) {
            Set<String> foundCodes = found.stream().map(RoleEntity::getCode).collect(Collectors.toSet());
            Set<String> missing = new LinkedHashSet<>(roleCodes);
            missing.removeAll(foundCodes);
            throw new RoleNotFoundException(missing);
        }
        return new LinkedHashSet<>(found);
    }
}
