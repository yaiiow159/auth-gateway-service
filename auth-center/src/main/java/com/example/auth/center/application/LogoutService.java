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
 * <p>兩枚憑證都必須處理，少任何一邊都會留下破口：
 * <ul>
 *   <li>只撤 Refresh Token —— 已外洩的 Access Token 在剩餘壽命內依然暢行無阻。</li>
 *   <li>只撤 Access Token —— Refresh Token 仍可換發新的憑證，登出形同虛設，
 *       而且它的壽命以「天」計算。</li>
 * </ul>
 *
 * <p>Refresh Token 透過 Access Token 的 {@code jti} 反查，因此客戶端不必在登出請求中
 * 附上 Refresh Token（前端通常也拿不到，它多半存在 HttpOnly Cookie 裡）。
 * 作廢範圍僅限本次工作階段，使用者在其他裝置上的登入不受影響。
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
            refreshTokenStore.consumeBySession(verified.tokenId());
            log.info("登出: userId={}, jti={}", verified.user().userId(), verified.tokenId());
        });
        // 客戶端若明確附上 Refresh Token 也一併作廢；Access Token 已過期而無法反查時，這是唯一的線索
        if (refreshTokenId != null && !refreshTokenId.isBlank()) {
            refreshTokenStore.consume(refreshTokenId);
        }
    }
}
