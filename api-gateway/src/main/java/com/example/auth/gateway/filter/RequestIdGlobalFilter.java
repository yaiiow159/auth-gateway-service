package com.example.auth.gateway.filter;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.gateway.support.FilterOrder;
import java.util.UUID;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 確保每個請求都有 Request Id，並回寫到回應中。
 *
 * <p>排在整條鏈的最前端，讓後續所有日誌與錯誤回應都能引用同一個識別碼。
 * 客訴進來時，一個 Request Id 就能串起網關、授權中心與各微服務的日誌，
 * 這在服務數量上去之後是排查問題的唯一實際手段。
 */
public class RequestIdGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestId = resolveRequestId(exchange.getRequest());
        exchange.getResponse().getHeaders().set(AuthHeaders.REQUEST_ID, requestId);

        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> headers.set(AuthHeaders.REQUEST_ID, requestId))
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    /** 沿用上游（例如 CDN 或前端）已產生的識別碼，讓追蹤鏈不會在網關斷掉。 */
    private static String resolveRequestId(ServerHttpRequest request) {
        String existing = request.getHeaders().getFirst(AuthHeaders.REQUEST_ID);
        return existing == null || existing.isBlank() ? UUID.randomUUID().toString() : existing;
    }

    @Override
    public int getOrder() {
        return FilterOrder.REQUEST_ID;
    }
}
