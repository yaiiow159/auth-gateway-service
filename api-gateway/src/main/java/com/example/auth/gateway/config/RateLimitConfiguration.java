package com.example.auth.gateway.config;

import com.example.auth.gateway.support.ClientAddresses;
import com.example.auth.gateway.support.ExchangeAttributes;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * 限流維度設定。
 *
 * <p>限流演算法直接採用 Spring Cloud Gateway 內建的 {@code RedisRateLimiter}
 * （Redis Lua 實作的權杖桶，具備跨副本一致性），這裡只需要決定「以什麼為單位限流」。
 * 自己重寫一套分散式限流器沒有必要，而且很難寫對。
 */
@Configuration(proxyBeanMethods = false)
public class RateLimitConfiguration {

    private static final String ANONYMOUS_KEY_PREFIX = "ip:";
    private static final String USER_KEY_PREFIX = "user:";

    /**
     * 已登入者以使用者為單位限流，匿名請求退回以來源 IP 為單位。
     *
     * <p>兩者加上不同前綴，避免「IP 為 1024 的匿名流量」與「使用者 1024」共用同一個配額。
     *
     * <p>注意：正式環境若前面還有 CDN 或負載均衡器，必須正確設定
     * {@code server.forward-headers-strategy}，否則取到的會是負載均衡器的 IP，
     * 導致所有匿名流量共用一個配額而互相影響。
     */
    @Bean
    public KeyResolver principalKeyResolver() {
        return exchange -> Mono.just(
                ExchangeAttributes.authenticatedUser(exchange)
                        .map(user -> USER_KEY_PREFIX + user.userId())
                        .orElseGet(() -> ANONYMOUS_KEY_PREFIX + ClientAddresses.of(exchange)));
    }
}
