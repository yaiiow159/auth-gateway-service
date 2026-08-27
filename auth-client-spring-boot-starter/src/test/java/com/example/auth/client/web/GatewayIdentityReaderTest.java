package com.example.auth.client.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.IdentitySignatures;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class GatewayIdentityReaderTest {

    private static final String SECRET = "shared-secret-for-tests";
    private static final Instant NOW = Instant.parse("2026-08-28T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Duration TTL = Duration.ofSeconds(60);

    private final GatewayIdentityReader reader = new GatewayIdentityReader(true, SECRET, TTL, CLOCK);

    @Test
    @DisplayName("解析網關注入的完整身分，包含 URL 編碼過的中文名稱")
    void readsIdentityInjectedByGateway() {
        AuthenticatedUser expected = new AuthenticatedUser(
                "1024", "王小明", Set.of("ROLE_ADMIN"), Set.of("order:read", "order:create"), "tenant-a");

        Optional<AuthenticatedUser> actual = reader.read(headersFor(expected)::get);

        assertThat(actual).contains(expected);
    }

    @Test
    @DisplayName("沒有 X-User-Id 時視為匿名請求")
    void returnsEmptyForAnonymousRequest() {
        assertThat(reader.read(name -> null)).isEmpty();
    }

    @Test
    @DisplayName("帶了身分卻沒有簽章時直接拒絕，不降級為匿名")
    void rejectsIdentityWithoutSignature() {
        Map<String, String> headers = headersFor(user());
        headers.remove(AuthHeaders.SIGNATURE);

        assertThatThrownBy(() -> reader.read(headers::get))
                .isInstanceOf(InvalidIdentitySignatureException.class);
    }

    @Test
    @DisplayName("竄改權限 Header 後簽章失效，請求被拒絕")
    void rejectsTamperedPermissionHeader() {
        Map<String, String> headers = headersFor(user());
        headers.put(AuthHeaders.PERMISSIONS, "order:read,order:delete");

        assertThatThrownBy(() -> reader.read(headers::get))
                .isInstanceOf(InvalidIdentitySignatureException.class)
                .hasMessageContaining("簽章驗證失敗");
    }

    @Test
    @DisplayName("關閉驗簽時不檢查簽章，適用於網路層已完全隔離的部署")
    void skipsVerificationWhenDisabled() {
        GatewayIdentityReader lenient = new GatewayIdentityReader(false, null, TTL, CLOCK);
        Map<String, String> headers = headersFor(user());
        headers.remove(AuthHeaders.SIGNATURE);

        assertThat(lenient.read(headers::get)).isPresent();
    }

    private static AuthenticatedUser user() {
        return new AuthenticatedUser("1024", "timmy", Set.of("ROLE_USER"), Set.of("order:read"), "tenant-a");
    }

    /** 模擬 IdentityPropagator 的輸出，確保兩端的編碼與簽章約定一致。 */
    private static Map<String, String> headersFor(AuthenticatedUser user) {
        Map<String, String> headers = new HashMap<>();
        headers.put(AuthHeaders.USER_ID, user.userId());
        headers.put(AuthHeaders.USERNAME, encode(user.username()));
        headers.put(AuthHeaders.TENANT_ID, encode(user.tenantId()));
        headers.put(AuthHeaders.ROLES, String.join(AuthHeaders.VALUE_DELIMITER, user.roles()));
        headers.put(AuthHeaders.PERMISSIONS, String.join(AuthHeaders.VALUE_DELIMITER, user.permissions()));
        headers.put(AuthHeaders.SIGNATURE, IdentitySignatures.sign(SECRET, user, NOW));
        return headers;
    }

    private static String encode(String value) {
        return value == null ? null : URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
