package com.example.auth.center.infrastructure.crypto;

import com.example.auth.center.domain.port.AccessTokenVerifier;
import com.example.auth.center.domain.port.RsaKeyProvider;
import com.example.auth.center.infrastructure.config.AuthTokenProperties;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.ClaimNames;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 以本地公鑰驗證 Access Token。
 *
 * <p>{@link DefaultJWTProcessor} 是執行緒安全的，因此在建構時組裝一次即可重複使用。
 * 金鑰來源以 lambda 委派給 {@link RsaKeyProvider}，讓金鑰輪替後不需要重建 processor。
 */
public class NimbusAccessTokenVerifier implements AccessTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(NimbusAccessTokenVerifier.class);

    private final DefaultJWTProcessor<SecurityContext> processor;

    public NimbusAccessTokenVerifier(RsaKeyProvider keyProvider, AuthTokenProperties properties) {
        this.processor = new DefaultJWTProcessor<>();
        this.processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                (jwkSelector, context) -> jwkSelector.select(keyProvider.publicJwkSet())));
        this.processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                properties.audience(),
                new JWTClaimsSet.Builder()
                        .issuer(properties.issuer())
                        .claim(ClaimNames.TOKEN_TYPE, ClaimNames.TYPE_ACCESS)
                        .build(),
                Set.of("sub", "exp", "jti")));
    }

    @Override
    public Optional<VerifiedToken> verify(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            JWTClaimsSet claims = processor.process(token, null);
            return Optional.of(new VerifiedToken(
                    toUser(claims),
                    claims.getJWTID(),
                    claims.getExpirationTime().toInstant()));
        } catch (Exception e) {
            // 驗證失敗是預期中的流程分支（過期、竄改、格式錯誤），不應該讓例外往外冒
            log.debug("Token 驗證未通過: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private static AuthenticatedUser toUser(JWTClaimsSet claims) {
        return new AuthenticatedUser(
                claims.getSubject(),
                asString(claims, ClaimNames.USERNAME),
                asSet(claims, ClaimNames.ROLES),
                asSet(claims, ClaimNames.PERMISSIONS),
                asString(claims, ClaimNames.TENANT_ID));
    }

    private static String asString(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : value.toString();
    }

    private static Set<String> asSet(JWTClaimsSet claims, String name) {
        try {
            List<String> values = claims.getStringListClaim(name);
            return values == null ? Set.of() : new LinkedHashSet<>(values);
        } catch (java.text.ParseException e) {
            return Set.of();
        }
    }
}
