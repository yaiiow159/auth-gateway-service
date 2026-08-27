package com.example.auth.center.application;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.port.RefreshTokenStore;
import com.example.auth.center.domain.port.UserAccountRepository;
import com.example.auth.center.domain.token.RefreshToken;
import com.example.auth.center.domain.token.TokenPair;
import com.example.auth.contract.AuthErrorCode;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Token 換發用例，採用 Refresh Token Rotation。
 *
 * <p>每次換發都會消耗舊的 Refresh Token 並發出新的一枚。若同一枚 Token 被使用第二次，
 * 代表它極可能已經外洩：合法客戶端手上的那枚早已被輪替掉，不會再送出來。
 *
 * <p>此時單純拒絕該次請求是不夠的。真正危險的情境是攻擊者搶先換發成功，
 * 受害者隨後才拿著舊 Token 撞上 401 —— 被拒絕的是受害者，而攻擊者手上那條
 * 輪替鏈仍然有效。因此偵測到重放時必須撤銷該使用者所有的 Refresh Token，
 * 讓雙方都被迫重新登入，攻擊鏈才會真正斷掉。
 */
@Service
public class TokenRefreshService {

    private static final Logger log = LoggerFactory.getLogger(TokenRefreshService.class);

    private final RefreshTokenStore refreshTokenStore;
    private final UserAccountRepository userAccountRepository;
    private final TokenPairFactory tokenPairFactory;
    private final Clock clock;

    public TokenRefreshService(RefreshTokenStore refreshTokenStore,
                               UserAccountRepository userAccountRepository,
                               TokenPairFactory tokenPairFactory,
                               Clock clock) {
        this.refreshTokenStore = refreshTokenStore;
        this.userAccountRepository = userAccountRepository;
        this.tokenPairFactory = tokenPairFactory;
        this.clock = clock;
    }

    public TokenPair refresh(String refreshTokenId) {
        RefreshToken consumed = refreshTokenStore.consume(refreshTokenId)
                .orElseThrow(() -> onConsumeFailed(refreshTokenId));

        if (consumed.isExpired(Instant.now(clock))) {
            throw new AuthenticationFailedException(AuthErrorCode.TOKEN_EXPIRED);
        }

        UserAccount account = userAccountRepository.findById(consumed.userId())
                .orElseThrow(() -> new AuthenticationFailedException(AuthErrorCode.TOKEN_INVALID));

        // 換發時重新檢查帳號狀態：使用者可能在 Access Token 有效期內被停權
        if (!account.canLogin()) {
            refreshTokenStore.revokeAll(account.id());
            throw new AuthenticationFailedException(AuthErrorCode.ACCOUNT_DISABLED);
        }

        log.debug("換發憑證: userId={}", account.id());
        return tokenPairFactory.createFor(account);
    }

    /**
     * 換發失敗時區分兩種情況：Token 從未存在（單純無效），或曾經存在但已被消耗（重放）。
     *
     * <p>對外一律回傳相同的錯誤碼，不讓呼叫端能藉由回應差異推敲出某枚 Token 是否曾經有效。
     */
    private AuthenticationFailedException onConsumeFailed(String refreshTokenId) {
        refreshTokenStore.ownerOfConsumedToken(refreshTokenId).ifPresent(owner -> {
            log.warn("偵測到 Refresh Token 重放，撤銷該使用者所有憑證: userId={}", owner);
            refreshTokenStore.revokeAll(owner);
        });
        return new AuthenticationFailedException(AuthErrorCode.TOKEN_INVALID);
    }
}
