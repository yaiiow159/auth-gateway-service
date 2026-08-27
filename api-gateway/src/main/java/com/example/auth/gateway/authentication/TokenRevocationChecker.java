package com.example.auth.gateway.authentication;

import reactor.core.publisher.Mono;

/** 查詢某枚 Token 是否已被撤銷。 */
@FunctionalInterface
public interface TokenRevocationChecker {

    Mono<Boolean> isRevoked(String tokenId);
}
