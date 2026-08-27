package com.example.auth.center.interfaces.rest.dto;

import com.example.auth.center.domain.token.TokenPair;
import java.time.Instant;

/**
 * 憑證回應，欄位命名對齊 OAuth2 慣例，讓既有的前端 SDK 可以直接使用。
 *
 * @param expiresIn Access Token 的剩餘秒數
 */
public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {

    private static final String BEARER = "Bearer";

    public static TokenResponse from(TokenPair pair, Instant now) {
        return new TokenResponse(
                pair.accessToken().value(),
                pair.refreshToken().value(),
                BEARER,
                pair.accessTokenExpiresInSeconds(now));
    }
}
