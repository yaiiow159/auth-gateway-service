package com.example.auth.center.infrastructure.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Token 相關設定。
 *
 * @param issuer                簽發者識別，網關會驗證此值
 * @param audience              受眾識別，避免 A 系統的 Token 被拿到 B 系統使用
 * @param accessTokenTtl        Access Token 存活時間，建議 5 到 15 分鐘
 * @param refreshTokenTtl       Refresh Token 存活時間
 * @param revocationKeyPrefix   撤銷名單的 Redis 鍵前綴，必須與網關設定一致
 * @param refreshTokenKeyPrefix Refresh Token 的 Redis 鍵前綴
 */
@ConfigurationProperties(prefix = "auth.token")
public record AuthTokenProperties(
        String issuer,
        String audience,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String revocationKeyPrefix,
        String refreshTokenKeyPrefix) {

    public AuthTokenProperties {
        issuer = defaultIfBlank(issuer, "https://auth.example.com");
        audience = defaultIfBlank(audience, "internal-api");
        accessTokenTtl = accessTokenTtl == null ? Duration.ofMinutes(10) : accessTokenTtl;
        refreshTokenTtl = refreshTokenTtl == null ? Duration.ofDays(14) : refreshTokenTtl;
        revocationKeyPrefix = defaultIfBlank(revocationKeyPrefix, "auth:revoked:");
        refreshTokenKeyPrefix = defaultIfBlank(refreshTokenKeyPrefix, "auth:refresh:");
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
