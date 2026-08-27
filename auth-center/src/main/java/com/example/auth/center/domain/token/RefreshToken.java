package com.example.auth.center.domain.token;

import com.example.auth.center.domain.model.UserId;
import java.time.Instant;

/**
 * Refresh Token 的持久化表述。
 *
 * <p>採用不透明（opaque）隨機字串而非 JWT：Refresh Token 本來就必須被伺服端記錄
 * 才能支援輪替與撤銷，既然狀態無法避免，就沒有理由再付出 JWT 的體積與解析成本。
 */
public record RefreshToken(String tokenId, UserId userId, Instant expiresAt) {

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
