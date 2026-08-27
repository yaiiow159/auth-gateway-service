package com.example.auth.center.domain.model;

import java.util.Objects;
import java.util.Set;

/**
 * 使用者帳號的領域模型。
 *
 * <p>刻意與 JPA Entity 分離：領域模型描述業務規則，Entity 描述資料表結構。
 * 兩者的變更理由不同（業務規則 vs 儲存結構），因此不該是同一個類別 —— 這是 SRP 的直接應用。
 *
 * @param roles       角色代碼，例如 {@code ROLE_ADMIN}
 * @param permissions 由角色展開後的權限碼，例如 {@code order:create}
 */
public record UserAccount(
        UserId id,
        String username,
        String passwordHash,
        String tenantId,
        AccountStatus status,
        Set<String> roles,
        Set<String> permissions) {

    public UserAccount {
        Objects.requireNonNull(id, "id 不可為 null");
        Objects.requireNonNull(username, "username 不可為 null");
        Objects.requireNonNull(passwordHash, "passwordHash 不可為 null");
        Objects.requireNonNull(status, "status 不可為 null");
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
    }

    public boolean canLogin() {
        return status == AccountStatus.ACTIVE;
    }
}
