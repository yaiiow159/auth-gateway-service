package com.example.auth.gateway.authentication;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthenticatedUser;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * 呼叫授權中心自省端點的驗證器（{@link TokenVerifier} 的另一種策略）。
 *
 * <p>預設不啟用。它存在的意義是把「驗證方式」保留為可替換的決策點：
 * 當需求變成「權限異動必須秒級生效」或「改用不透明 Token」時，
 * 只要切換設定即可，過濾器、授權策略、Header 注入全都不受影響。
 *
 * <p>採用這條路線時務必補上斷路器（Resilience4j）與快取，否則授權中心會成為
 * 全站流量的同步依賴 —— 它一慢，所有請求跟著慢。
 */
public class RemoteIntrospectionTokenVerifier implements TokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(RemoteIntrospectionTokenVerifier.class);
    private static final String INTROSPECTION_PATH = "/internal/tokens/introspect";

    private final WebClient webClient;
    private final Duration timeout;

    public RemoteIntrospectionTokenVerifier(WebClient webClient, Duration timeout) {
        this.webClient = webClient;
        this.timeout = timeout;
    }

    @Override
    public Mono<AuthenticationResult> verify(String rawToken) {
        return webClient.post()
                .uri(INTROSPECTION_PATH)
                .bodyValue(Map.of("token", rawToken))
                .retrieve()
                .bodyToMono(IntrospectionPayload.class)
                .timeout(timeout)
                .map(RemoteIntrospectionTokenVerifier::toResult)
                .onErrorResume(error -> {
                    log.error("呼叫授權中心自省端點失敗", error);
                    return Mono.just(AuthenticationResult.failure(
                            AuthErrorCode.AUTH_CENTER_UNAVAILABLE, error.getMessage()));
                });
    }

    private static AuthenticationResult toResult(IntrospectionPayload payload) {
        if (!payload.active()) {
            return AuthenticationResult.failure(AuthErrorCode.TOKEN_INVALID, "introspection returned inactive");
        }
        AuthenticatedUser user = new AuthenticatedUser(
                payload.userId(), payload.username(), payload.roles(), payload.permissions(), payload.tenantId());
        return AuthenticationResult.success(user, payload.tokenId());
    }

    /** 自省端點的回應結構，與授權中心的 {@code IntrospectionResponse} 對應。 */
    private record IntrospectionPayload(
            boolean active,
            String userId,
            String username,
            Set<String> roles,
            Set<String> permissions,
            String tenantId,
            String tokenId) {
    }
}
