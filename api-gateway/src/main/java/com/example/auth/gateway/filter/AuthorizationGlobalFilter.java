package com.example.auth.gateway.filter;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.gateway.authorization.AccessContext;
import com.example.auth.gateway.authorization.AccessDecision;
import com.example.auth.gateway.authorization.AccessPolicyChain;
import com.example.auth.gateway.support.ExchangeAttributes;
import com.example.auth.gateway.support.FilterOrder;
import com.example.auth.gateway.support.ProblemResponseWriter;
import java.util.Locale;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 授權過濾器：對已認證的請求做粗粒度的路徑層級判定。
 *
 * <p>網關這一層只處理「這個角色能不能碰這條路由」，細到資料列層級的判斷
 * （例如「這張訂單是不是他自己的」）必須留在各微服務內部 ——
 * 網關沒有業務資料，也不該為了授權而去查業務資料庫。
 *
 * <p>屬性中沒有身分時代表請求走的是免認證路徑，直接放行。
 */
public class AuthorizationGlobalFilter implements GlobalFilter, Ordered {

    private final AccessPolicyChain accessPolicyChain;
    private final ProblemResponseWriter problemResponseWriter;

    public AuthorizationGlobalFilter(AccessPolicyChain accessPolicyChain,
                                     ProblemResponseWriter problemResponseWriter) {
        this.accessPolicyChain = accessPolicyChain;
        this.problemResponseWriter = problemResponseWriter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ExchangeAttributes.authenticatedUser(exchange)
                .map(user -> decide(exchange, chain, toContext(exchange.getRequest(), user)))
                .orElseGet(() -> chain.filter(exchange));
    }

    private Mono<Void> decide(ServerWebExchange exchange, GatewayFilterChain chain, AccessContext context) {
        AccessDecision decision = accessPolicyChain.evaluate(context);
        return decision == AccessDecision.PERMIT
                ? chain.filter(exchange)
                : problemResponseWriter.write(exchange, AuthErrorCode.ACCESS_DENIED,
                        "policy chain decided " + decision);
    }

    private static AccessContext toContext(ServerHttpRequest request, com.example.auth.contract.AuthenticatedUser user) {
        String method = request.getMethod().name().toUpperCase(Locale.ROOT);
        return new AccessContext(request.getPath().pathWithinApplication().value(), method, user);
    }

    @Override
    public int getOrder() {
        return FilterOrder.AUTHORIZATION;
    }
}
