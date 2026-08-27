package com.example.auth.center.application;

import com.example.auth.center.domain.port.AccessTokenVerifier;
import com.example.auth.center.domain.port.RefreshTokenStore;
import com.example.auth.center.domain.port.TokenRevocationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 登出用例：同時作廢 Access Token 與 Refresh Token。
 *
 * <p>只刪 Refresh Token 是常見的實作疏漏，那會讓已外洩的 Access Token
 * 在剩餘壽命內依然暢行無阻。
 */
@Service
public class LogoutService {

    private static final Logger log = LoggerFactory.getLogger(LogoutService.class);

    private final AccessTokenVerifier accessTokenVerifier;
    private final TokenRevocationStore revocationStore;
    private final RefreshTokenStore refreshTokenStore;

    public LogoutService(AccessTokenVerifier accessTokenVerifier,
                         TokenRevocationStore revocationStore,
                         RefreshTokenStore refreshTokenStore) {
        this.accessTokenVerifier = accessTokenVerifier;
        this.revocationStore = revocationStore;
        this.refreshTokenStore = refreshTokenStore;
    }

    /**
     * 登出。
     *
     * <p>本方法對「無效的 Token」保持沉默：登出是冪等操作，重複呼叫或帶著過期 Token 呼叫
     * 都應該視為成功，否則前端得為了登出寫一堆錯誤處理。
     */
    public void logout(String accessToken, String refreshTokenId) {
        accessTokenVerifier.verify(accessToken).ifPresent(verified -> {
            revocationStore.revoke(verified.tokenId(), verified.expiresAt());
            log.info("撤銷 Access Token: userId={}, jti={}", verified.user().userId(), verified.tokenId());
        });
        if (refreshTokenId != null && !refreshTokenId.isBlank()) {
            refreshTokenStore.consume(refreshTokenId);
        }
    }
}
