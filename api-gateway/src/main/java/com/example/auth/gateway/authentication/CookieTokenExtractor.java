package com.example.auth.gateway.authentication;

import java.util.Optional;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * 從 Cookie 取出 Token，供無法自訂 Header 的瀏覽器情境使用。
 *
 * <p>採用 Cookie 傳遞憑證時必須搭配 {@code SameSite=Lax/Strict} 與 CSRF 防護，
 * 否則等於把 CSRF 攻擊面重新打開。
 */
public class CookieTokenExtractor implements TokenExtractor {

    private final String cookieName;

    public CookieTokenExtractor(String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public Optional<String> extract(ServerHttpRequest request) {
        return Optional.ofNullable(request.getCookies().getFirst(cookieName))
                .map(HttpCookie::getValue)
                .filter(value -> !value.isBlank());
    }
}
