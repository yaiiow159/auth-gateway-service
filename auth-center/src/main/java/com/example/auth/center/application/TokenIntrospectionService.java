package com.example.auth.center.application;

import com.example.auth.center.domain.port.AccessTokenVerifier;
import com.example.auth.center.domain.port.TokenRevocationStore;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Token 自省用例：驗簽加上撤銷檢查，回傳完整身分。
 *
 * <p>供採用「遠端驗證」策略的網關或非 JVM 邊緣元件呼叫。
 */
@Service
public class TokenIntrospectionService {

    private final AccessTokenVerifier accessTokenVerifier;
    private final TokenRevocationStore revocationStore;

    public TokenIntrospectionService(AccessTokenVerifier accessTokenVerifier,
                                     TokenRevocationStore revocationStore) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.revocationStore = revocationStore;
    }

    public Optional<AccessTokenVerifier.VerifiedToken> introspect(String token) {
        return accessTokenVerifier.verify(token)
                .filter(verified -> !revocationStore.isRevoked(verified.tokenId()));
    }
}
