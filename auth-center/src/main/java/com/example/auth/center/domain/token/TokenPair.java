package com.example.auth.center.domain.token;

import java.time.Duration;
import java.time.Instant;

/**
 * 登入或換發後回傳給客戶端的憑證組。
 *
 * <p>Access Token 短命（分鐘級）以縮小外洩的影響範圍；Refresh Token 長命但一次性，
 * 每次換發都會輪替（rotation），舊的立即失效。
 */
public record TokenPair(IssuedToken accessToken, IssuedToken refreshToken) {

    public long accessTokenExpiresInSeconds(Instant now) {
        return Math.max(0, Duration.between(now, accessToken.expiresAt()).toSeconds());
    }
}
