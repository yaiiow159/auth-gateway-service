package com.example.auth.gateway.authentication;

import reactor.core.publisher.Mono;

/**
 * Token 驗證策略。
 *
 * <p>目前有兩種實作路線：
 * <ul>
 *   <li>{@link JwtTokenVerifier}：以 JWKS 公鑰在網關本地驗簽，零網路往返，是預設路線。</li>
 *   <li>{@link RemoteIntrospectionTokenVerifier}：呼叫授權中心自省端點，適用於不透明 Token
 *       或需要即時反映權限異動的場景，代價是每個請求多一次網路往返。</li>
 * </ul>
 * 兩者可透過設定切換，甚至用 {@link RevocationAwareTokenVerifier} 疊加組合，
 * 而認證過濾器完全不需要知道背後用的是哪一種。
 */
public interface TokenVerifier {

    Mono<AuthenticationResult> verify(String rawToken);
}
