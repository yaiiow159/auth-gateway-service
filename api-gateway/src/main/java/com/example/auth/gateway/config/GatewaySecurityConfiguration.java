package com.example.auth.gateway.config;

import com.example.auth.gateway.authentication.PublicEndpointMatcher;
import com.example.auth.gateway.authentication.TokenExtractor;
import com.example.auth.gateway.authentication.TokenVerifier;
import com.example.auth.gateway.authorization.AccessPolicy;
import com.example.auth.gateway.authorization.AccessPolicyChain;
import com.example.auth.gateway.authorization.RuleBasedAccessPolicy;
import com.example.auth.gateway.authorization.SuperRoleAccessPolicy;
import com.example.auth.gateway.filter.AuthenticationGlobalFilter;
import com.example.auth.gateway.filter.AuthorizationGlobalFilter;
import com.example.auth.gateway.filter.IdentityPropagationGlobalFilter;
import com.example.auth.gateway.filter.PreAuthRateLimitGlobalFilter;
import com.example.auth.gateway.filter.RequestIdGlobalFilter;
import com.example.auth.gateway.identity.IdentityPropagator;
import com.example.auth.gateway.identity.IdentitySigningPolicy;
import com.example.auth.gateway.support.ProblemResponseWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 網關安全管線的組裝點。
 *
 * <p>整條鏈的順序、每個環節用什麼實作，全部在這一個檔案裡交代完畢。
 * 想理解「一個請求進到網關後會經過什麼」，讀這裡與 {@code FilterOrder} 就夠了。
 */
@Configuration(proxyBeanMethods = false)
public class GatewaySecurityConfiguration {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public ProblemResponseWriter problemResponseWriter(ObjectMapper objectMapper, Clock clock) {
        return new ProblemResponseWriter(objectMapper, clock);
    }

    @Bean
    public AccessPolicy superRoleAccessPolicy(GatewayAuthProperties properties) {
        return new SuperRoleAccessPolicy(properties.authorization().superRole());
    }

    @Bean
    public AccessPolicy ruleBasedAccessPolicy(GatewayAuthProperties properties) {
        return new RuleBasedAccessPolicy(properties.authorization().rules());
    }

    /**
     * 責任鏈接受所有 {@link AccessPolicy} 型別的 Bean。
     *
     * <p>這是刻意留下的擴充點：日後要加入 IP 白名單、營業時間限制或 OPA 遠端判定，
     * 只需要新增一個 Bean 並指定 {@code order()}，這個檔案不需要修改。
     */
    @Bean
    public AccessPolicyChain accessPolicyChain(List<AccessPolicy> policies, GatewayAuthProperties properties) {
        return new AccessPolicyChain(policies, properties.authorization().defaultDecision());
    }

    /**
     * 將設定值轉換成領域型別 {@link IdentitySigningPolicy}，轉換只發生在這個組裝點。
     *
     * <p>設定的合法性由該型別自身把關；不合法時拋出的例外會被 Spring 包成
     * {@code BeanCreationException}，應用程式啟動即失敗。
     */
    @Bean
    public IdentityPropagator identityPropagator(GatewayAuthProperties properties, Clock clock) {
        GatewayAuthProperties.Identity identity = properties.identity();
        IdentitySigningPolicy signingPolicy = identity.signingEnabled()
                ? IdentitySigningPolicy.signingWith(identity.signingSecret())
                : IdentitySigningPolicy.disabled();
        return new IdentityPropagator(signingPolicy, clock);
    }

    @Bean
    public RequestIdGlobalFilter requestIdGlobalFilter() {
        return new RequestIdGlobalFilter();
    }

    /**
     * 認證前的 IP 限流，沿用 Spring Cloud Gateway 內建的 Redis 權杖桶實作。
     */
    @Bean
    @ConditionalOnProperty(prefix = "gateway.auth.pre-auth-rate-limit", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    public PreAuthRateLimitGlobalFilter preAuthRateLimitGlobalFilter(RedisRateLimiter redisRateLimiter,
                                                                     ProblemResponseWriter problemResponseWriter,
                                                                     GatewayAuthProperties properties) {
        GatewayAuthProperties.PreAuthRateLimit config = properties.preAuthRateLimit();
        return new PreAuthRateLimitGlobalFilter(redisRateLimiter, problemResponseWriter,
                config.replenishRate(), config.burstCapacity());
    }

    @Bean
    public AuthenticationGlobalFilter authenticationGlobalFilter(PublicEndpointMatcher publicEndpointMatcher,
                                                                 TokenExtractor tokenExtractor,
                                                                 TokenVerifier tokenVerifier,
                                                                 ProblemResponseWriter problemResponseWriter) {
        return new AuthenticationGlobalFilter(
                publicEndpointMatcher, tokenExtractor, tokenVerifier, problemResponseWriter);
    }

    @Bean
    public AuthorizationGlobalFilter authorizationGlobalFilter(AccessPolicyChain accessPolicyChain,
                                                               ProblemResponseWriter problemResponseWriter) {
        return new AuthorizationGlobalFilter(accessPolicyChain, problemResponseWriter);
    }

    @Bean
    public IdentityPropagationGlobalFilter identityPropagationGlobalFilter(IdentityPropagator identityPropagator) {
        return new IdentityPropagationGlobalFilter(identityPropagator);
    }
}
