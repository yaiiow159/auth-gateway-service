package com.example.auth.contract;

import java.util.Objects;
import java.util.Set;

/**
 * 已通過認證的使用者身分，是網關與下游服務之間唯一的身分表述。
 *
 * <p>設計為不可變的 value object：一旦網關完成驗證，這份身分在整個請求生命週期中
 * 不應該再被任何一段程式碼修改。
 *
 * @param userId      使用者唯一識別碼，不可為空
 * @param username    登入帳號，可為 {@code null}（例如機器對機器的 Token）
 * @param roles       角色代碼集合
 * @param permissions 權限碼集合
 * @param tenantId    租戶識別碼，單租戶部署時為 {@code null}
 */
public record AuthenticatedUser(
        String userId,
        String username,
        Set<String> roles,
        Set<String> permissions,
        String tenantId) {

    public AuthenticatedUser {
        Objects.requireNonNull(userId, "userId 不可為 null");
        if (userId.isBlank()) {
            throw new IllegalArgumentException("userId 不可為空白");
        }
        // 防禦性複製 + 不可變化，避免呼叫端在外部持有可變參考
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean hasAnyPermission(Set<String> required) {
        return required.isEmpty() || required.stream().anyMatch(permissions::contains);
    }

    public boolean hasAllPermissions(Set<String> required) {
        return permissions.containsAll(required);
    }
}
