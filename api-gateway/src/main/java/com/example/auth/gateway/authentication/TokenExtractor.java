package com.example.auth.gateway.authentication;

import java.util.Optional;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * 從請求中取出原始 Token 的策略。
 *
 * <p>抽成介面是為了應付現實中的多來源需求：瀏覽器端可能用 HttpOnly Cookie，
 * 行動端與服務間呼叫則用 Authorization Header。這些差異不該汙染認證過濾器的主流程。
 */
@FunctionalInterface
public interface TokenExtractor {

    Optional<String> extract(ServerHttpRequest request);
}
