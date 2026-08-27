package com.example.auth.center.domain.token;

import java.time.Instant;
import java.util.Objects;

/**
 * 一枚已簽發的 Token。
 *
 * @param value     Token 字串本體
 * @param tokenId   Token 的唯一識別碼（JWT 的 {@code jti}），撤銷時以此為鍵
 * @param expiresAt 到期時間，用來決定撤銷紀錄在 Redis 中的 TTL
 */
public record IssuedToken(String value, String tokenId, Instant expiresAt) {

    public IssuedToken {
        Objects.requireNonNull(value, "value 不可為 null");
        Objects.requireNonNull(tokenId, "tokenId 不可為 null");
        Objects.requireNonNull(expiresAt, "expiresAt 不可為 null");
    }
}
