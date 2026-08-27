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
 * 代表它極可能已經外洩（合法客戶端手上的那枚早已被輪替掉）。
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
                .orElseThrow(() -> new AuthenticationFailedException(AuthErrorCode.TOKEN_INVALID));

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
}
