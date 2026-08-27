package com.example.auth.center.infrastructure.crypto;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.port.AccessTokenIssuer;
import com.example.auth.center.domain.port.RsaKeyProvider;
import com.example.auth.center.domain.token.IssuedToken;
import com.example.auth.center.infrastructure.config.AuthTokenProperties;
import com.example.auth.contract.ClaimNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * 以 RS256 簽發 Access Token。
 *
 * <p>選用非對稱簽章（RS256）而非 HS256 的理由：網關與所有微服務只需要公鑰即可驗證，
 * 私鑰不必散佈到任何一個副本之外。若使用 HS256，密鑰必須分發給每個驗證方，
 * 任何一個服務被入侵都等同於整個系統的簽發能力外洩。
 */
public class NimbusAccessTokenIssuer implements AccessTokenIssuer {

    private final RsaKeyProvider keyProvider;
    private final AuthTokenProperties properties;
    private final Clock clock;

    public NimbusAccessTokenIssuer(RsaKeyProvider keyProvider, AuthTokenProperties properties, Clock clock) {
        this.keyProvider = keyProvider;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public IssuedToken issue(UserAccount account) {
        Instant issuedAt = Instant.now(clock);
        Instant expiresAt = issuedAt.plus(properties.accessTokenTtl());
        String tokenId = UUID.randomUUID().toString();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(account.id().value())
                .issuer(properties.issuer())
                .audience(properties.audience())
                .jwtID(tokenId)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim(ClaimNames.USERNAME, account.username())
                .claim(ClaimNames.ROLES, List.copyOf(account.roles()))
                .claim(ClaimNames.PERMISSIONS, List.copyOf(account.permissions()))
                .claim(ClaimNames.TENANT_ID, account.tenantId())
                .claim(ClaimNames.TOKEN_TYPE, ClaimNames.TYPE_ACCESS)
                .build();

        return new IssuedToken(sign(claims), tokenId, expiresAt);
    }

    private String sign(JWTClaimsSet claims) {
        RSAKey key = keyProvider.signingKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new RSASSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException("Access Token 簽章失敗", e);
        }
        return jwt.serialize();
    }
}
