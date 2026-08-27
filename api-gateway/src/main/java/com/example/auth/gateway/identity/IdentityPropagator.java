package com.example.auth.gateway.identity;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.IdentitySignatures;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * 身分 Header 的注入與消毒。
 *
 * <p><b>這是整套架構的安全樞紐。</b>下游微服務之所以敢直接信任 {@code X-User-Id}，
 * 唯一的理由就是「網關保證這個 Header 只可能由自己寫入」。因此兩件事缺一不可：
 * <ol>
 *   <li><b>先剝除：</b>不論請求有沒有通過認證，一律移除客戶端帶進來的所有身分 Header。
 *       少了這一步，任何人只要自己加一個 {@code X-User-Id: 1} 就成了管理員。</li>
 *   <li><b>再簽章：</b>對注入的內容做 HMAC，讓下游即使被繞過網關直連也能識破偽造請求（零信任）。</li>
 * </ol>
 *
 * <p>使用者名稱與租戶識別碼以 URL encoding 處理後才寫入 Header：HTTP Header 只保證能承載
 * ASCII，中文暱稱之類的內容若直接塞入，輕則亂碼、重則被代理伺服器截斷。
 * 簽章計算的是「編碼前」的原始值，下游必須先解碼再驗章。
 */
public class IdentityPropagator {

    private final boolean signingEnabled;
    private final String signingSecret;
    private final Clock clock;

    public IdentityPropagator(boolean signingEnabled, String signingSecret, Clock clock) {
        this.signingEnabled = signingEnabled;
        this.signingSecret = signingSecret;
        this.clock = clock;
    }

    /** 匿名請求：只做消毒，不注入任何身分。 */
    public ServerHttpRequest withoutIdentity(ServerHttpRequest request) {
        return request.mutate().headers(IdentityPropagator::removeForgeableHeaders).build();
    }

    /** 已認證請求：消毒後注入可信身分。 */
    public ServerHttpRequest withTrustedIdentity(ServerHttpRequest request, AuthenticatedUser user) {
        return request.mutate()
                .headers(headers -> {
                    removeForgeableHeaders(headers);
                    writeIdentity(headers, user);
                })
                .build();
    }

    private static void removeForgeableHeaders(HttpHeaders headers) {
        AuthHeaders.CLIENT_FORGEABLE.forEach(headers::remove);
    }

    private void writeIdentity(HttpHeaders headers, AuthenticatedUser user) {
        headers.set(AuthHeaders.USER_ID, user.userId());
        setIfPresent(headers, AuthHeaders.USERNAME, encode(user.username()));
        setIfPresent(headers, AuthHeaders.TENANT_ID, encode(user.tenantId()));
        setIfPresent(headers, AuthHeaders.ROLES, join(user.roles()));
        setIfPresent(headers, AuthHeaders.PERMISSIONS, join(user.permissions()));

        if (signingEnabled) {
            headers.set(AuthHeaders.SIGNATURE, IdentitySignatures.sign(signingSecret, user, Instant.now(clock)));
        }
    }

    private static void setIfPresent(HttpHeaders headers, String name, String value) {
        if (value != null && !value.isEmpty()) {
            headers.set(name, value);
        }
    }

    private static String join(Set<String> values) {
        return String.join(AuthHeaders.VALUE_DELIMITER, values);
    }

    private static String encode(String value) {
        return value == null ? null : URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
