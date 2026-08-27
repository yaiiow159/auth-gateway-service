package com.example.auth.gateway.filter;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.gateway.support.ClientAddresses;
import com.example.auth.gateway.support.FilterOrder;
import com.example.auth.gateway.support.ProblemResponseWriter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 認證之前的粗粒度限流，以來源 IP 為單位。
 *
 * <p>路由層的 {@code RequestRateLimiter} 排在認證之後，才能依使用者身分做細緻的配額管理；
 * 但那也意味著每一個最終被擋下的請求，都已經先付出了一次 RSA 驗簽與一次 Redis 查詢。
 * 面對單一 Token 的高速灌流量，網關的 CPU 會被消耗在注定要丟棄的請求上。
 *
 * <p>這道過濾器補上前半段：在任何昂貴運算之前，先用 IP 擋掉明顯異常的流量。
 * 兩者是互補而非重複 —— 這裡的配額必須設得比路由層寬鬆，它要擋的是攻擊而不是正常尖峰。
 *
 * <p>限流演算法直接沿用 Spring Cloud Gateway 內建的 {@link RedisRateLimiter}
 * （Redis Lua 實作的權杖桶，跨副本一致），只是換一個更早的執行時機。
 */
public class PreAuthRateLimitGlobalFilter implements GlobalFilter, Ordered {

    /** 供 RedisRateLimiter 查找設定用的合成路由識別，不對應任何真實路由。 */
    static final String ROUTE_ID = "pre-auth-ip-rate-limit";

    private static final String KEY_PREFIX = "ip:";

    private final RedisRateLimiter rateLimiter;
    private final ProblemResponseWriter problemResponseWriter;

    public PreAuthRateLimitGlobalFilter(RedisRateLimiter rateLimiter,
                                        ProblemResponseWriter problemResponseWriter,
                                        int replenishRate,
                                        int burstCapacity) {
        this.rateLimiter = rateLimiter;
        this.problemResponseWriter = problemResponseWriter;
        // RedisRateLimiter 依 routeId 查找設定，這裡為合成路由註冊一組專屬配額
        this.rateLimiter.getConfig().put(ROUTE_ID,
                new RedisRateLimiter.Config()
                        .setReplenishRate(replenishRate)
                        .setBurstCapacity(burstCapacity));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return rateLimiter.isAllowed(ROUTE_ID, KEY_PREFIX + ClientAddresses.of(exchange))
                .flatMap(response -> response.isAllowed()
                        ? chain.filter(exchange)
                        : problemResponseWriter.write(
                                exchange, AuthErrorCode.RATE_LIMITED, "pre-auth ip rate limit exceeded"));
    }

    @Override
    public int getOrder() {
        return FilterOrder.PRE_AUTH_RATE_LIMIT;
    }
}
