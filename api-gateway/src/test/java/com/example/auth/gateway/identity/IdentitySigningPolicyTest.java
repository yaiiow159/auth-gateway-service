package com.example.auth.gateway.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.IdentitySignatures;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class IdentitySigningPolicyTest {

    private static final String SECRET = "gateway-and-service-shared-secret";
    private static final Instant NOW = Instant.parse("2026-08-28T10:00:00Z");

    private static final AuthenticatedUser USER = new AuthenticatedUser(
            "2048", "timmy", Set.of("ROLE_USER"), Set.of("order:read"), "tenant-a");

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    @DisplayName("「啟用簽章但沒有密鑰」是一個無法被建構出來的狀態")
    void cannotRepresentEnabledWithoutSecret(String blankSecret) {
        assertThatThrownBy(() -> IdentitySigningPolicy.signingWith(blankSecret))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("gateway.auth.identity.signing-secret");
    }

    @Test
    @DisplayName("產生的簽章可被下游以相同密鑰驗證通過")
    void producesSignatureVerifiableWithSharedSecret() {
        String signature = IdentitySigningPolicy.signingWith(SECRET)
                .signatureFor(USER, NOW)
                .orElseThrow();

        assertThat(IdentitySignatures.verify(SECRET, USER, signature, NOW, Duration.ofSeconds(60))).isTrue();
    }

    @Test
    @DisplayName("未啟用簽章時不產生簽章，且不需要密鑰")
    void producesNoSignatureWhenDisabled() {
        assertThat(IdentitySigningPolicy.disabled().signatureFor(USER, NOW)).isEmpty();
    }
}
