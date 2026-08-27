package com.example.auth.center.infrastructure.persistence;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Entity 到領域模型的轉換。
 *
 * <p>轉換過程中會把「角色 -> 權限」的樹狀結構攤平成扁平的權限碼集合：
 * 下游只關心「這個人能不能做這件事」，不需要知道權限是從哪個角色繼承來的。
 */
final class UserAccountMapper {

    private UserAccountMapper() {
    }

    static UserAccount toDomain(UserEntity entity) {
        return new UserAccount(
                UserId.of(entity.getId()),
                entity.getUsername(),
                entity.getPasswordHash(),
                entity.getTenantId(),
                entity.getStatus(),
                roleCodesOf(entity),
                permissionCodesOf(entity));
    }

    private static Set<String> roleCodesOf(UserEntity entity) {
        return entity.getRoles().stream()
                .map(RoleEntity::getCode)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static Set<String> permissionCodesOf(UserEntity entity) {
        return entity.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(PermissionEntity::getCode)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
