package com.example.auth.gateway.authentication;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthenticatedUser;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreaker;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * 呼叫授權中心自省端點的驗證器（{@link TokenVerifier} 的另一種策略）。
 *
 * <p>預設不啟用。它存在的意義是把「驗證方式」保留為可替換的決策點：
 * 當需求變成「權限異動必須秒級生效」或「改用不透明 Token」時，
 * 只要切換設定即可，過濾器、授權策略、Header 注入全都不受影響。
 *
 * <p>這條路線把授權中心變成每個請求的同步依賴，因此兩道保護缺一不可：
 * <ul>
 *   <li><b>斷路器</b>（由建構子注入）—— 授權中心持續失敗時直接快速失敗，
 *       而不是讓每個請求都耗掉一次逾時等待。沒有它，下游變慢會讓網關的
 *       待處理請求無限堆積，故障從一個服務擴散成全站不可用。</li>
 *   <li><b>結果快取</b>（由 {@link CachingTokenVerifier} 疊加）—— 削掉同一枚 Token
 *       重複自省的尖峰。</li>
 * </ul>
 */
public class RemoteIntrospectionTokenVerifier implements TokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(RemoteIntrospectionTokenVerifier.class);
    private static final String INTROSPECTION_PATH = "/internal/tokens/introspect";

    private final WebClient webClient;
    private final Duration timeout;
    private final ReactiveCircuitBreaker circuitBreaker;

    public RemoteIntrospectionTokenVerifier(WebClient webClient, Duration timeout,
                                            ReactiveCircuitBreaker circuitBreaker) {
        this.webClient = webClient;
        this.timeout = timeout;
        this.circuitBreaker = circuitBreaker;
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
                .transform(response -> circuitBreaker.run(response, this::unavailable));
    }

    /**
     * 斷路器開啟或呼叫失敗時的退路。
     *
     * <p>刻意回傳失敗而非放行：授權中心無法回應時，網關沒有任何依據可以認定這枚 Token 有效，
     * 此時「拒絕」是唯一安全的選擇。這與撤銷名單的 failOpen 是不同性質的決定 ——
     * 那裡至少還有一份通過驗簽的 Token 作為依據。
     */
    private Mono<AuthenticationResult> unavailable(Throwable error) {
        log.error("呼叫授權中心自省端點失敗，回傳服務不可用", error);
        return Mono.just(AuthenticationResult.failure(
                AuthErrorCode.AUTH_CENTER_UNAVAILABLE, error.getMessage()));
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
