package com.example.auth.gateway.config;

import com.example.auth.contract.ClaimNames;
import com.example.auth.gateway.authentication.BearerTokenExtractor;
import com.example.auth.gateway.authentication.CompositeTokenExtractor;
import com.example.auth.gateway.authentication.CookieTokenExtractor;
import com.example.auth.gateway.authentication.JwtTokenVerifier;
import com.example.auth.gateway.authentication.PublicEndpointMatcher;
import com.example.auth.gateway.authentication.RedisTokenRevocationChecker;
import com.example.auth.gateway.authentication.RemoteIntrospectionTokenVerifier;
import com.example.auth.gateway.authentication.RevocationAwareTokenVerifier;
import com.example.auth.gateway.authentication.TokenExtractor;
import com.example.auth.gateway.authentication.TokenRevocationChecker;
import com.example.auth.gateway.authentication.TokenVerifier;
import java.util.List;
import java.util.Objects;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * 認證相關元件的組裝。
 *
 * <p>驗證器在這裡以「基礎策略 + 裝飾器」的方式組合出來：
 * 先依設定選出本地驗簽或遠端自省，再視需要包上撤銷檢查。
 * 組裝邏輯集中於此，過濾器只認得 {@link TokenVerifier} 介面。
 */
@Configuration(proxyBeanMethods = false)
public class TokenVerificationConfiguration {

    private static final String TOKEN_COOKIE_NAME = "access_token";
    private static final int CLOCK_SKEW_SECONDS = 30;

    @Bean
    public PublicEndpointMatcher publicEndpointMatcher(GatewayAuthProperties properties) {
        return new PublicEndpointMatcher(properties.publicPaths());
    }

    /** Header 優先於 Cookie，避免瀏覽器殘留的舊 Cookie 蓋掉明確指定的憑證。 */
    @Bean
    public TokenExtractor tokenExtractor() {
        return new CompositeTokenExtractor(List.of(
                new BearerTokenExtractor(),
                new CookieTokenExtractor(TOKEN_COOKIE_NAME)));
    }

    /**
     * JWKS 解碼器。
     *
     * <p>{@link NimbusReactiveJwtDecoder} 內部會快取 JWKS 並在遇到未知的 {@code kid} 時
     * 自動重抓，因此授權中心輪替金鑰後不需要重啟網關。
     */
    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(GatewayAuthProperties properties) {
        GatewayAuthProperties.Jwt jwt = properties.jwt();
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(jwt.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(jwtValidator(jwt));
        return decoder;
    }

    /**
     * 驗簽通過只代表「這張票是我們發的」，還必須逐條檢查它是不是「發給這裡、現在還有效」。
     *
     * <ul>
     *   <li>時間戳：允許 30 秒時鐘偏移，避免分散式環境下的誤判。</li>
     *   <li>簽發者與受眾：擋下把其他系統的合法 Token 拿來用的橫向移動。</li>
     *   <li>Token 類型：擋下拿 Refresh Token 當 Access Token 用的提權手法。</li>
     *   <li>{@code jti} 必須存在：沒有它就無法被撤銷，等於一張收不回來的通行證。</li>
     * </ul>
     */
    private static OAuth2TokenValidator<Jwt> jwtValidator(GatewayAuthProperties.Jwt jwt) {
        JwtTimestampValidator timestampValidator = new JwtTimestampValidator(
                java.time.Duration.ofSeconds(CLOCK_SKEW_SECONDS));
        return new DelegatingOAuth2TokenValidator<>(
                timestampValidator,
                new JwtIssuerValidator(jwt.issuer()),
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        audiences -> audiences != null && audiences.contains(jwt.audience())),
                new JwtClaimValidator<String>(ClaimNames.TOKEN_TYPE, ClaimNames.TYPE_ACCESS::equals),
                new JwtClaimValidator<String>(JwtClaimNames.JTI, Objects::nonNull));
    }

    @Bean
    public TokenRevocationChecker tokenRevocationChecker(GatewayAuthProperties properties,
                                                         ReactiveStringRedisTemplate redisTemplate) {
        GatewayAuthProperties.Revocation revocation = properties.revocation();
        return new RedisTokenRevocationChecker(redisTemplate, revocation.keyPrefix(), revocation.failOpen());
    }

    @Bean
    public TokenVerifier tokenVerifier(GatewayAuthProperties properties,
                                       ReactiveJwtDecoder jwtDecoder,
                                       TokenRevocationChecker revocationChecker,
                                       WebClient.Builder webClientBuilder) {
        TokenVerifier baseVerifier = switch (properties.verificationMode()) {
            case LOCAL -> new JwtTokenVerifier(jwtDecoder);
            case REMOTE -> new RemoteIntrospectionTokenVerifier(
                    webClientBuilder.baseUrl(properties.remote().baseUrl()).build(),
                    properties.remote().timeout());
        };
        // 遠端自省已經在授權中心那側查過撤銷名單，不需要在網關重複查一次
        boolean needsRevocationCheck = properties.revocation().enabled()
                && properties.verificationMode() == GatewayAuthProperties.VerificationMode.LOCAL;
        return needsRevocationCheck
                ? new RevocationAwareTokenVerifier(baseVerifier, revocationChecker)
                : baseVerifier;
    }
}
