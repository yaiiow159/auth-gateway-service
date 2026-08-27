package com.example.auth.gateway.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.IdentitySignatures;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

class IdentityPropagatorTest {

    private static final String SECRET = "gateway-and-service-shared-secret";
    private static final Instant NOW = Instant.parse("2026-08-28T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static final AuthenticatedUser USER = new AuthenticatedUser(
            "2048", "王小明", Set.of("ROLE_USER"), Set.of("order:read", "order:create"), "tenant-a");

    private final IdentityPropagator propagator = new IdentityPropagator(true, SECRET, CLOCK);

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    @DisplayName("啟用簽章卻沒有密鑰時，物件無法被建構出來")
    void rejectsSigningEnabledWithoutSecret(String blankSecret) {
        assertThatThrownBy(() -> new IdentityPropagator(true, blankSecret, CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("gateway.auth.identity.signing-secret");
    }

    @Test
    @DisplayName("未啟用簽章時允許沒有密鑰")
    void allowsMissingSecretWhenSigningDisabled() {
        assertThatNoException().isThrownBy(() -> new IdentityPropagator(false, null, CLOCK));
    }

    @Test
    @DisplayName("匿名請求：客戶端偽造的身分 Header 全數被剝除，且不注入任何身分")
    void stripsForgedHeadersFromAnonymousRequest() {
        ServerHttpRequest sanitized = propagator.withoutIdentity(requestWithForgedIdentity());

        assertThat(sanitized.getHeaders().keySet())
                .doesNotContainAnyElementsOf(AuthHeaders.CLIENT_FORGEABLE);
    }

    @Test
    @DisplayName("已認證請求：偽造內容被覆蓋為網關驗證後的真實身分")
    void overwritesForgedHeadersWithVerifiedIdentity() {
        HttpHeaders headers = propagator.withTrustedIdentity(requestWithForgedIdentity(), USER).getHeaders();

        assertThat(headers.getFirst(AuthHeaders.USER_ID)).isEqualTo("2048");
        assertThat(headers.getFirst(AuthHeaders.ROLES)).isEqualTo("ROLE_USER");
        assertThat(split(headers.getFirst(AuthHeaders.PERMISSIONS)))
                .containsExactlyInAnyOrder("order:read", "order:create");
    }

    @Test
    @DisplayName("非 ASCII 的使用者名稱以 URL encoding 寫入，避免 Header 亂碼或被代理截斷")
    void urlEncodesNonAsciiHeaderValues() {
        HttpHeaders headers = propagator.withTrustedIdentity(anonymousRequest(), USER).getHeaders();
        String encoded = headers.getFirst(AuthHeaders.USERNAME);

        assertThat(encoded).isNotNull().doesNotContain("王");
        assertThat(URLDecoder.decode(encoded, StandardCharsets.UTF_8)).isEqualTo("王小明");
    }

    @Test
    @DisplayName("注入的簽章可被下游以共享密鑰驗證通過")
    void producesSignatureVerifiableByDownstreamService() {
        String signature = propagator.withTrustedIdentity(anonymousRequest(), USER)
                .getHeaders().getFirst(AuthHeaders.SIGNATURE);

        assertThat(IdentitySignatures.verify(SECRET, USER, signature, NOW, Duration.ofSeconds(60))).isTrue();
    }

    @Test
    @DisplayName("關閉簽章時不寫入簽章 Header")
    void omitsSignatureWhenSigningDisabled() {
        IdentityPropagator unsigned = new IdentityPropagator(false, null, CLOCK);

        HttpHeaders headers = unsigned.withTrustedIdentity(anonymousRequest(), USER).getHeaders();

        assertThat(headers.getFirst(AuthHeaders.SIGNATURE)).isNull();
    }

    private static ServerHttpRequest anonymousRequest() {
        return MockServerHttpRequest.get("/api/orders").build();
    }

    /** 模擬攻擊者自行帶上身分 Header 想冒充管理員。 */
    private static ServerHttpRequest requestWithForgedIdentity() {
        return MockServerHttpRequest.get("/api/orders")
                .header(AuthHeaders.USER_ID, "1")
                .header(AuthHeaders.USERNAME, "root")
                .header(AuthHeaders.ROLES, "ROLE_SUPER_ADMIN")
                .header(AuthHeaders.PERMISSIONS, "order:delete")
                .header(AuthHeaders.TENANT_ID, "tenant-evil")
                .header(AuthHeaders.SIGNATURE, "forged.signature")
                .build();
    }

    private static String[] split(String value) {
        return value == null ? new String[0] : value.split(AuthHeaders.VALUE_DELIMITER);
    }
}
