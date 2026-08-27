package com.example.auth.gateway.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthenticatedUser;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class RevocationAwareTokenVerifierTest {

    private static final String TOKEN = "any-token";
    private static final String TOKEN_ID = "jti-1";

    private static final AuthenticatedUser USER =
            new AuthenticatedUser("1024", "timmy", Set.of("ROLE_USER"), Set.of("order:read"), "tenant-a");

    @Test
    @DisplayName("未被撤銷時原樣回傳成功結果")
    void passesThroughWhenTokenIsNotRevoked() {
        TokenVerifier verifier = new RevocationAwareTokenVerifier(
                successVerifier(), tokenId -> Mono.just(false));

        StepVerifier.create(verifier.verify(TOKEN))
                .assertNext(result -> assertThat(result).isInstanceOf(AuthenticationResult.Success.class))
                .verifyComplete();
    }

    @Test
    @DisplayName("已被撤銷時轉為 TOKEN_REVOKED 失敗")
    void failsWhenTokenIsRevoked() {
        TokenVerifier verifier = new RevocationAwareTokenVerifier(
                successVerifier(), tokenId -> Mono.just(true));

        StepVerifier.create(verifier.verify(TOKEN))
                .assertNext(result -> assertThat(result)
                        .isInstanceOf(AuthenticationResult.Failure.class)
                        .extracting(failure -> ((AuthenticationResult.Failure) failure).errorCode())
                        .isEqualTo(AuthErrorCode.TOKEN_REVOKED))
                .verifyComplete();
    }

    @Test
    @DisplayName("驗簽就失敗時直接短路，不查撤銷名單")
    void skipsRevocationLookupWhenSignatureVerificationFails() {
        AtomicInteger lookupCount = new AtomicInteger();
        TokenVerifier verifier = new RevocationAwareTokenVerifier(
                rawToken -> Mono.just(AuthenticationResult.failure(AuthErrorCode.TOKEN_INVALID, "bad signature")),
                tokenId -> {
                    lookupCount.incrementAndGet();
                    return Mono.just(false);
                });

        StepVerifier.create(verifier.verify(TOKEN))
                .assertNext(result -> assertThat(result).isInstanceOf(AuthenticationResult.Failure.class))
                .verifyComplete();

        assertThat(lookupCount).hasValue(0);
    }

    private static TokenVerifier successVerifier() {
        return rawToken -> Mono.just(AuthenticationResult.success(USER, TOKEN_ID));
    }
}
