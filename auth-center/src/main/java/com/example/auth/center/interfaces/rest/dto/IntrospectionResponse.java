package com.example.auth.center.interfaces.rest.dto;

import com.example.auth.center.domain.port.AccessTokenVerifier;
import java.util.Set;

/**
 * Token 自省回應。
 *
 * <p>Token 無效時只回傳 {@code active=false}，不透露失敗原因 ——
 * 這是 RFC 7662 的建議，避免自省端點被當成 Token 破解的預言機（oracle）。
 */
public record IntrospectionResponse(
        boolean active,
        String userId,
        String username,
        Set<String> roles,
        Set<String> permissions,
        String tenantId,
        String tokenId,
        Long expiresAt) {

    private static final IntrospectionResponse INACTIVE =
            new IntrospectionResponse(false, null, null, null, null, null, null, null);

    public static IntrospectionResponse inactive() {
        return INACTIVE;
    }

    public static IntrospectionResponse active(AccessTokenVerifier.VerifiedToken verified) {
        var user = verified.user();
        return new IntrospectionResponse(
                true,
                user.userId(),
                user.username(),
                user.roles(),
                user.permissions(),
                user.tenantId(),
                verified.tokenId(),
                verified.expiresAt().getEpochSecond());
    }
}
