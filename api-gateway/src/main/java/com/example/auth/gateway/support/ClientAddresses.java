package com.example.auth.gateway.support;

import java.util.Optional;
import org.springframework.web.server.ServerWebExchange;

/**
 * 取得客戶端來源位址。
 *
 * <p>依賴 {@code server.forward-headers-strategy}：網關前若還有 CDN 或負載均衡器而未正確設定，
 * 取到的會是負載均衡器的位址，所有匿名流量將共用同一個限流配額而互相影響。
 */
public final class ClientAddresses {

    private static final String UNKNOWN = "unknown";

    private ClientAddresses() {
        throw new AssertionError("工具類別不應被實例化");
    }

    public static String of(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                .map(address -> address.getAddress() == null ? UNKNOWN : address.getAddress().getHostAddress())
                .orElse(UNKNOWN);
    }
}
