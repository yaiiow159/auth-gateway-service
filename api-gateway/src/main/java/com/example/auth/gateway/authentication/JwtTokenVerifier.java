package com.example.auth.gateway.authentication;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.ClaimNames;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

/**
 * 以本地公鑰驗簽的 Token 驗證器，這是整套架構高吞吐的來源。
 *
 * <p>驗簽是純 CPU 運算（RSA 公鑰驗證），不會阻塞事件迴圈；
 * JWKS 的抓取與快取由 {@link ReactiveJwtDecoder} 內部以非阻塞方式處理。
 */
public class JwtTokenVerifier implements TokenVerifier {

    private static final String EXPIRED_MARKER = "expired";

    private final ReactiveJwtDecoder jwtDecoder;

    public JwtTokenVerifier(ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<AuthenticationResult> verify(String rawToken) {
        return jwtDecoder.decode(rawToken)
                .map(JwtTokenVerifier::toSuccess)
                // 順序不可調換：JwtValidationException 是 JwtException 的子型別
                .onErrorResume(JwtValidationException.class, e -> Mono.just(toFailure(e)))
                .onErrorResume(JwtException.class,
                        e -> Mono.just(AuthenticationResult.failure(AuthErrorCode.TOKEN_INVALID, e.getMessage())));
    }

    private static AuthenticationResult toSuccess(Jwt jwt) {
        AuthenticatedUser user = new AuthenticatedUser(
                jwt.getSubject(),
                jwt.getClaimAsString(ClaimNames.USERNAME),
                toSet(jwt.getClaimAsStringList(ClaimNames.ROLES)),
                toSet(jwt.getClaimAsStringList(ClaimNames.PERMISSIONS)),
                jwt.getClaimAsString(ClaimNames.TENANT_ID));
        return AuthenticationResult.success(user, jwt.getId());
    }

    /**
     * 區分「過期」與「無效」。
     *
     * <p>兩者的 HTTP 狀態同為 401，但前端的處理方式完全不同：過期應該靜默換發並重試，
     * 無效則必須把使用者導回登入頁。不區分的話，前端只能對所有 401 一律登出，體驗會很糟。
     */
    private static AuthenticationResult toFailure(JwtValidationException e) {
        boolean expired = e.getErrors().stream()
                .map(error -> String.valueOf(error.getDescription()).toLowerCase(Locale.ROOT))
                .anyMatch(description -> description.contains(EXPIRED_MARKER));
        AuthErrorCode errorCode = expired ? AuthErrorCode.TOKEN_EXPIRED : AuthErrorCode.TOKEN_INVALID;
        return AuthenticationResult.failure(errorCode, e.getMessage());
    }

    private static Set<String> toSet(List<String> values) {
        return values == null ? Set.of() : new LinkedHashSet<>(values);
    }
}
