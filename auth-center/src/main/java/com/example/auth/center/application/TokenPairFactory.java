package com.example.auth.center.application;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.port.AccessTokenIssuer;
import com.example.auth.center.domain.port.RefreshTokenStore;
import com.example.auth.center.domain.token.IssuedToken;
import com.example.auth.center.domain.token.RefreshToken;
import com.example.auth.center.domain.token.TokenPair;
import org.springframework.stereotype.Component;

/**
 * 憑證組的組裝工廠。
 *
 * <p>登入與換發都需要「簽一張 Access Token + 發一張 Refresh Token」，
 * 把這段組裝集中在工廠裡，日後要加入裝置指紋、MFA 等級等 Claim 時只有一個修改點。
 */
@Component
public class TokenPairFactory {

    private final AccessTokenIssuer accessTokenIssuer;
    private final RefreshTokenStore refreshTokenStore;

    public TokenPairFactory(AccessTokenIssuer accessTokenIssuer, RefreshTokenStore refreshTokenStore) {
        this.accessTokenIssuer = accessTokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
    }

    public TokenPair createFor(UserAccount account) {
        IssuedToken accessToken = accessTokenIssuer.issue(account);
        RefreshToken refreshToken = refreshTokenStore.issue(account.id());
        return new TokenPair(
                accessToken,
                new IssuedToken(refreshToken.tokenId(), refreshToken.tokenId(), refreshToken.expiresAt()));
    }
}
