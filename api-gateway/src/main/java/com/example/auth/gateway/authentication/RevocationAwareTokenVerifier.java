package com.example.auth.gateway.authentication;

import com.example.auth.contract.AuthErrorCode;
import reactor.core.publisher.Mono;

/**
 * 在既有驗證器之上加掛撤銷檢查的裝飾器（Decorator）。
 *
 * <p>「驗簽」與「查撤銷名單」是兩個獨立變化的關注點：前者取決於密碼學與金鑰管理，
 * 後者取決於快取架構。用裝飾器組合而非塞進同一個類別，讓兩邊可以各自被替換與測試。
 *
 * <p>只有驗簽成功才查 Redis —— 對於偽造的 Token 直接短路，避免無效流量打進快取層。
 */
public class RevocationAwareTokenVerifier implements TokenVerifier {

    private final TokenVerifier delegate;
    private final TokenRevocationChecker revocationChecker;

    public RevocationAwareTokenVerifier(TokenVerifier delegate, TokenRevocationChecker revocationChecker) {
        this.delegate = delegate;
        this.revocationChecker = revocationChecker;
    }

    @Override
    public Mono<AuthenticationResult> verify(String rawToken) {
        return delegate.verify(rawToken).flatMap(result -> switch (result) {
            case AuthenticationResult.Failure failure -> Mono.just(failure);
            case AuthenticationResult.Success success -> rejectIfRevoked(success);
        });
    }

    private Mono<AuthenticationResult> rejectIfRevoked(AuthenticationResult.Success success) {
        return revocationChecker.isRevoked(success.tokenId())
                .map(revoked -> revoked
                        ? AuthenticationResult.failure(AuthErrorCode.TOKEN_REVOKED, "token in revocation list")
                        : success);
    }
}
