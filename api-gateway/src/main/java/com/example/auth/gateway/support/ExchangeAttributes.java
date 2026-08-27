package com.example.auth.gateway.support;

import com.example.auth.contract.AuthenticatedUser;
import java.util.Optional;
import org.springframework.web.server.ServerWebExchange;

/**
 * 過濾器之間傳遞狀態的具型別存取點。
 *
 * <p>直接對 {@code exchange.getAttributes()} 寫入字串鍵是常見的維護災難：
 * 鍵名散落各處、型別靠強制轉型、拼錯只會得到 null。這個類別把鍵名收斂成唯一來源，
 * 並讓讀取端拿到 {@link Optional} 而不是可能為 null 的物件。
 */
public final class ExchangeAttributes {

    private static final String AUTHENTICATED_USER = ExchangeAttributes.class.getName() + ".AUTHENTICATED_USER";

    private ExchangeAttributes() {
        throw new AssertionError("工具類別不應被實例化");
    }

    public static void setAuthenticatedUser(ServerWebExchange exchange, AuthenticatedUser user) {
        exchange.getAttributes().put(AUTHENTICATED_USER, user);
    }

    public static Optional<AuthenticatedUser> authenticatedUser(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getAttribute(AUTHENTICATED_USER));
    }
}
