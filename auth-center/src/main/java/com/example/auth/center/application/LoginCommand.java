package com.example.auth.center.application;

import java.util.Objects;

/**
 * 登入指令。
 *
 * <p>與 REST 層的 DTO 分開，讓應用層不必因為 API 版本演進（v1/v2 的欄位差異）而變動。
 */
public record LoginCommand(String username, String rawPassword) {

    public LoginCommand {
        Objects.requireNonNull(username, "username 不可為 null");
        Objects.requireNonNull(rawPassword, "rawPassword 不可為 null");
    }
}
