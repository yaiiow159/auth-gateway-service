package com.example.auth.gateway.identity;

import com.example.auth.contract.AuthHeaders;
import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.HeaderCodec;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
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
 *   <li><b>再簽章：</b>依 {@link IdentitySigningPolicy} 對注入的內容做 HMAC，
 *       讓下游即使被繞過網關直連也能識破偽造請求（零信任）。</li>
 * </ol>
 *
 * <p>所有寫入 Header 的值都先經過 {@link HeaderCodec} 編碼，角色與權限則是逐一編碼後才串接。
 * HTTP Header 只保證能承載 ASCII，中文暱稱直接塞入輕則亂碼、重則被代理截斷；
 * 而角色代碼若含有分隔用的逗號，未編碼時會在下游被拆成兩個角色，且簽章察覺不到。
 * 簽章計算的是「編碼前」的原始值，下游必須先解碼再驗章。
 */
public class IdentityPropagator {

    private final IdentitySigningPolicy signingPolicy;
    private final Clock clock;

    public IdentityPropagator(IdentitySigningPolicy signingPolicy, Clock clock) {
        this.signingPolicy = Objects.requireNonNull(signingPolicy, "signingPolicy 不可為 null");
        this.clock = Objects.requireNonNull(clock, "clock 不可為 null");
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

        signingPolicy.signatureFor(user, Instant.now(clock))
                .ifPresent(signature -> headers.set(AuthHeaders.SIGNATURE, signature));
    }

    private static void setIfPresent(HttpHeaders headers, String name, String value) {
        if (value != null && !value.isEmpty()) {
            headers.set(name, value);
        }
    }

    private static String join(Set<String> values) {
        return HeaderCodec.encodeList(values);
    }

    private static String encode(String value) {
        return HeaderCodec.encodeValue(value);
    }
}
