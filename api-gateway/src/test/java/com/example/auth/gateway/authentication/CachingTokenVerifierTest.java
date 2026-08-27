package com.example.auth.gateway.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthenticatedUser;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class CachingTokenVerifierTest {

    private static final String TOKEN = "a-token";
    private static final AuthenticatedUser USER =
            new AuthenticatedUser("2048", "timmy", Set.of("ROLE_USER"), Set.of("order:read"), null);

    @Test
    @DisplayName("相同 Token 在存活期間內只會呼叫下游一次")
    void callsDelegateOnceForRepeatedToken() {
        AtomicInteger calls = new AtomicInteger();
        TokenVerifier verifier = caching(counting(calls, AuthenticationResult.success(USER, "jti-1")));

        verifier.verify(TOKEN).block();
        verifier.verify(TOKEN).block();
        verifier.verify(TOKEN).block();

        assertThat(calls).hasValue(1);
    }

    @Test
    @DisplayName("不同 Token 各自查詢，不會互相污染")
    void doesNotShareResultsAcrossTokens() {
        AtomicInteger calls = new AtomicInteger();
        TokenVerifier verifier = caching(counting(calls, AuthenticationResult.success(USER, "jti-1")));

        verifier.verify("token-a").block();
        verifier.verify("token-b").block();

        assertThat(calls).hasValue(2);
    }

    @Test
    @DisplayName("失敗結果同樣被快取，避免無效 Token 的重複探測打穿下游")
    void cachesFailuresToo() {
        AtomicInteger calls = new AtomicInteger();
        TokenVerifier verifier = caching(counting(calls,
                AuthenticationResult.failure(AuthErrorCode.TOKEN_INVALID, "bad token")));

        StepVerifier.create(verifier.verify(TOKEN))
                .assertNext(result -> assertThat(result).isInstanceOf(AuthenticationResult.Failure.class))
                .verifyComplete();
        verifier.verify(TOKEN).block();

        assertThat(calls).hasValue(1);
    }

    @Test
    @DisplayName("存活時間為零時不快取，每次都重新查詢")
    void doesNotCacheWhenTtlIsZero() {
        AtomicInteger calls = new AtomicInteger();
        TokenVerifier verifier = new CachingTokenVerifier(
                counting(calls, AuthenticationResult.success(USER, "jti-1")), Duration.ZERO, 100);

        verifier.verify(TOKEN).block();
        verifier.verify(TOKEN).block();

        assertThat(calls).hasValue(2);
    }

    private static TokenVerifier caching(TokenVerifier delegate) {
        return new CachingTokenVerifier(delegate, Duration.ofSeconds(30), 100);
    }

    private static TokenVerifier counting(AtomicInteger calls, AuthenticationResult result) {
        return rawToken -> Mono.fromSupplier(() -> {
            calls.incrementAndGet();
            return result;
        });
    }
}
