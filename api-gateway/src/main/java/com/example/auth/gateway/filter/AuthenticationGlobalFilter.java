package com.example.auth.gateway.filter;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.gateway.authentication.AuthenticationResult;
import com.example.auth.gateway.authentication.PublicEndpointMatcher;
import com.example.auth.gateway.authentication.TokenExtractor;
import com.example.auth.gateway.authentication.TokenVerifier;
import com.example.auth.gateway.support.ExchangeAttributes;
import com.example.auth.gateway.support.FilterOrder;
import com.example.auth.gateway.support.ProblemResponseWriter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 認證過濾器：取出 Token、驗證、把身分放進 exchange 屬性。
 *
 * <p>它只負責「你是誰」，完全不碰「你能做什麼」。這條界線讓授權模型（RBAC/ABAC/OPA）
 * 可以獨立演進，而不必動到認證流程。
 */
public class AuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private final PublicEndpointMatcher publicEndpointMatcher;
    private final TokenExtractor tokenExtractor;
    private final TokenVerifier tokenVerifier;
    private final ProblemResponseWriter problemResponseWriter;

    public AuthenticationGlobalFilter(PublicEndpointMatcher publicEndpointMatcher,
                                      TokenExtractor tokenExtractor,
                                      TokenVerifier tokenVerifier,
                                      ProblemResponseWriter problemResponseWriter) {
        this.publicEndpointMatcher = publicEndpointMatcher;
        this.tokenExtractor = tokenExtractor;
        this.tokenVerifier = tokenVerifier;
        this.problemResponseWriter = problemResponseWriter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (publicEndpointMatcher.isPublic(exchange.getRequest())) {
            return chain.filter(exchange);
        }
        return tokenExtractor.extract(exchange.getRequest())
                .map(token -> authenticate(exchange, chain, token))
                .orElseGet(() -> problemResponseWriter.write(
                        exchange, AuthErrorCode.TOKEN_MISSING, "no credential in request"));
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, GatewayFilterChain chain, String token) {
        return tokenVerifier.verify(token).flatMap(result -> switch (result) {
            case AuthenticationResult.Success success -> {
                ExchangeAttributes.setAuthenticatedUser(exchange, success.user());
                yield chain.filter(exchange);
            }
            case AuthenticationResult.Failure failure ->
                    problemResponseWriter.write(exchange, failure.errorCode(), failure.detail());
        });
    }

    @Override
    public int getOrder() {
        return FilterOrder.AUTHENTICATION;
    }
}
