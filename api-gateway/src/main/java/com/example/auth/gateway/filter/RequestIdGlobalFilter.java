package com.example.auth.gateway.filter;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.gateway.support.FilterOrder;
import java.util.UUID;
import java.util.regex.Pattern;
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

    /** 追蹤識別碼的安全格式：僅英數與少數符號，長度上限 128。 */
    private static final Pattern SAFE_REQUEST_ID = Pattern.compile("[A-Za-z0-9._-]{1,128}");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestId = resolveRequestId(exchange.getRequest());
        exchange.getResponse().getHeaders().set(AuthHeaders.REQUEST_ID, requestId);

        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> headers.set(AuthHeaders.REQUEST_ID, requestId))
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    /**
     * 沿用上游（例如 CDN 或前端）已產生的識別碼，讓追蹤鏈不會在網關斷掉。
     *
     * <p>但只在它符合安全格式時才沿用。這個值會被寫進日誌並轉發給所有下游服務，
     * 直接採信等於讓任何人都能以換行字元偽造日誌行來掩蓋自己的足跡，
     * 或以超長字串把每一筆相關日誌撐大。格式不符時一律改用自行產生的識別碼。
     */
    private static String resolveRequestId(ServerHttpRequest request) {
        String existing = request.getHeaders().getFirst(AuthHeaders.REQUEST_ID);
        return existing != null && SAFE_REQUEST_ID.matcher(existing).matches()
                ? existing
                : UUID.randomUUID().toString();
    }

    @Override
    public int getOrder() {
        return FilterOrder.REQUEST_ID;
    }
}
