package com.example.auth.center.interfaces.rest.dto;

import com.example.auth.center.domain.model.AccountStatus;
import com.example.auth.center.domain.model.UserAccount;
import java.util.Set;

/**
 * 帳號回應。
 *
 * <p>刻意不含 {@code passwordHash}：即使是管理端點也沒有任何理由把雜湊值送出去，
 * 它一旦離開伺服端就多了一份離線破解的樣本。
 */
public record UserResponse(
        String id,
        String username,
        String tenantId,
        AccountStatus status,
        Set<String> roles,
        Set<String> permissions) {

    public static UserResponse from(UserAccount account) {
        return new UserResponse(
                account.id().value(),
                account.username(),
                account.tenantId(),
                account.status(),
                account.roles(),
                account.permissions());
    }
}
