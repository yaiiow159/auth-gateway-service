package com.example.auth.center.application;

import java.util.Objects;
import java.util.Set;

/**
 * 建立帳號指令。
 *
 * @param roleCodes 初始角色；允許為空，代表建立一個尚未授權的帳號
 */
public record CreateUserCommand(String username, String rawPassword, String tenantId, Set<String> roleCodes) {

    public CreateUserCommand {
        Objects.requireNonNull(username, "username 不可為 null");
        Objects.requireNonNull(rawPassword, "rawPassword 不可為 null");
        roleCodes = roleCodes == null ? Set.of() : Set.copyOf(roleCodes);
    }
}
