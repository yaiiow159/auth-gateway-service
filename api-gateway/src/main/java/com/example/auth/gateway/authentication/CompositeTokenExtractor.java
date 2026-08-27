package com.example.auth.gateway.authentication;

import java.util.List;
import java.util.Optional;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * 依序嘗試多個來源，取到就停（組合模式）。
 *
 * <p>順序即優先權：Header 應排在 Cookie 之前，讓明確帶上 Authorization 的呼叫端
 * 不會被瀏覽器殘留的舊 Cookie 蓋掉。
 */
public class CompositeTokenExtractor implements TokenExtractor {

    private final List<TokenExtractor> delegates;

    public CompositeTokenExtractor(List<TokenExtractor> delegates) {
        this.delegates = List.copyOf(delegates);
    }

    @Override
    public Optional<String> extract(ServerHttpRequest request) {
        return delegates.stream()
                .map(delegate -> delegate.extract(request))
                .flatMap(Optional::stream)
                .findFirst();
    }
}
