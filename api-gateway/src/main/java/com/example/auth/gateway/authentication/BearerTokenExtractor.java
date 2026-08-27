package com.example.auth.gateway.authentication;

import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

/** 從 {@code Authorization: Bearer <token>} 取出 Token。 */
public class BearerTokenExtractor implements TokenExtractor {

    private static final String PREFIX = "Bearer ";

    @Override
    public Optional<String> extract(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            return Optional.empty();
        }
        String token = header.substring(PREFIX.length()).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }
}
