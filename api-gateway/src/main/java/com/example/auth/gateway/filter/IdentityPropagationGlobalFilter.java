package com.example.auth.gateway.filter;

import com.example.auth.gateway.identity.IdentityPropagator;
import com.example.auth.gateway.support.ExchangeAttributes;
import com.example.auth.gateway.support.FilterOrder;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 身分傳遞過濾器：把已驗證的身分轉成下游看得懂的 Header。
 *
 * <p><b>它對每一個請求都會執行，包含免認證路徑</b> —— 因為「剝除客戶端偽造的身分 Header」
 * 這件事在匿名請求上同樣重要。如果只在認證成功時才做消毒，攻擊者只要挑一條公開端點，
 * 就能把偽造的 {@code X-User-Id} 一路送進後端服務。
 */
public class IdentityPropagationGlobalFilter implements GlobalFilter, Ordered {

    private final IdentityPropagator identityPropagator;

    public IdentityPropagationGlobalFilter(IdentityPropagator identityPropagator) {
        this.identityPropagator = identityPropagator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = ExchangeAttributes.authenticatedUser(exchange)
                .map(user -> identityPropagator.withTrustedIdentity(exchange.getRequest(), user))
                .orElseGet(() -> identityPropagator.withoutIdentity(exchange.getRequest()));

        return chain.filter(exchange.mutate().request(request).build());
    }

    @Override
    public int getOrder() {
        return FilterOrder.IDENTITY_PROPAGATION;
    }
}
