package com.example.auth.gateway.config;

import com.example.auth.gateway.authorization.AccessDecision;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 網關認證與授權的全部設定。
 *
 * <p>把所有開關收斂成一個具型別的設定樹，好處是：新人只要讀這個檔案就能知道網關有哪些行為可調，
 * 而且拼錯的設定鍵會在啟動時就被 IDE 或 Actuator 的 configprops 端點揪出來，
 * 不會變成執行期才發現的「設定沒生效」。
 */
@ConfigurationProperties(prefix = "gateway.auth")
public record GatewayAuthProperties(
        VerificationMode verificationMode,
        List<String> publicPaths,
        Jwt jwt,
        Remote remote,
        Revocation revocation,
        Identity identity,
        Authorization authorization) {

    public GatewayAuthProperties {
        verificationMode = verificationMode == null ? VerificationMode.LOCAL : verificationMode;
        publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
        jwt = jwt == null ? new Jwt(null, null, null) : jwt;
        remote = remote == null ? new Remote(null, null) : remote;
        revocation = revocation == null ? new Revocation(null, null, null) : revocation;
        identity = identity == null ? new Identity(null, null) : identity;
        authorization = authorization == null ? new Authorization(null, null, null) : authorization;
    }

    /**
     * Token 的驗證路線。
     *
     * <p>這是本架構最核心的一個取捨開關，兩種模式的差異詳見 docs/adr/0001。
     */
    public enum VerificationMode {

        /** 以 JWKS 公鑰在網關本地驗簽，零網路往返。 */
        LOCAL,

        /** 每個請求呼叫授權中心自省端點，權限異動可即時生效但延遲較高。 */
        REMOTE
    }

    /**
     * 遠端驗證模式的連線設定，僅在 {@link VerificationMode#REMOTE} 下生效。
     *
     * @param baseUrl 授權中心的內部位址
     * @param timeout 單次自省呼叫的逾時上限；沒有逾時就等於把網關的執行緒交給下游決定
     */
    public record Remote(String baseUrl, Duration timeout) {

        public Remote {
            baseUrl = orDefault(baseUrl, "http://localhost:9000");
            timeout = timeout == null ? Duration.ofMillis(500) : timeout;
        }
    }

    /**
     * JWT 驗簽設定。
     *
     * @param jwkSetUri 授權中心的 JWKS 位址；解碼器會自行快取與更新，不需要每次請求抓取
     * @param issuer    預期的簽發者，必須與授權中心一致
     * @param audience  預期的受眾，用來擋下「拿別套系統的 Token 來存取」
     */
    public record Jwt(String jwkSetUri, String issuer, String audience) {

        public Jwt {
            jwkSetUri = orDefault(jwkSetUri, "http://localhost:9000/.well-known/jwks.json");
            issuer = orDefault(issuer, "https://auth.example.com");
            audience = orDefault(audience, "internal-api");
        }
    }

    /**
     * 撤銷名單檢查設定。
     *
     * @param enabled   是否啟用；關閉後登出的 Token 會在剩餘壽命內繼續有效
     * @param keyPrefix Redis 鍵前綴，必須與授權中心的 {@code auth.token.revocation-key-prefix} 一致
     * @param failOpen  Redis 不可用時的行為，見 {@code RevocationAwareTokenVerifier} 的說明
     */
    public record Revocation(Boolean enabled, String keyPrefix, Boolean failOpen) {

        public Revocation {
            enabled = enabled == null || enabled;
            keyPrefix = orDefault(keyPrefix, "auth:revoked:");
            failOpen = failOpen == null || failOpen;
        }
    }

    /**
     * 身分 Header 注入設定。
     *
     * <p>此處沒有「簽章有效期間」的設定：簽章方只負責蓋上時間戳，
     * 「多久以內的簽章還算數」是驗章方的風險決策，設定在下游服務的
     * {@code auth.client.signature-ttl}。放一個不會被讀取的同名設定只會誤導維運。
     *
     * @param signingEnabled 是否對注入的身分做 HMAC 簽章，讓下游能獨立驗證來源
     * @param signingSecret  與下游服務共享的密鑰，務必由環境變數或 Secret 注入
     */
    public record Identity(Boolean signingEnabled, String signingSecret) {

        public Identity {
            signingEnabled = signingEnabled != null && signingEnabled;
        }
    }

    /**
     * 授權規則設定。
     *
     * @param defaultDecision 所有規則都未命中時的兜底判定
     * @param superRole       擁有此角色即放行任何路徑，通常是維運或平台管理角色
     * @param rules           路徑層級的規則，由上而下比對，第一條命中者生效
     */
    public record Authorization(AccessDecision defaultDecision, String superRole, List<Rule> rules) {

        public Authorization {
            defaultDecision = defaultDecision == null ? AccessDecision.DENY : defaultDecision;
            superRole = orDefault(superRole, "ROLE_SUPER_ADMIN");
            rules = rules == null ? List.of() : List.copyOf(rules);
        }
    }

    /**
     * 單一路徑規則。三個條件同時設定時必須全部滿足。
     *
     * @param path              Ant 風格路徑樣式，例如 {@code /api/orders/**}
     * @param methods           HTTP 方法；留空代表不限方法
     * @param anyOfPermissions  擁有其中任一權限即可
     * @param allOfPermissions  必須同時擁有全部權限
     * @param anyOfRoles        擁有其中任一角色即可
     */
    public record Rule(
            String path,
            Set<String> methods,
            Set<String> anyOfPermissions,
            Set<String> allOfPermissions,
            Set<String> anyOfRoles) {

        public Rule {
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("授權規則的 path 不可為空");
            }
            methods = upperCase(methods);
            anyOfPermissions = nullToEmpty(anyOfPermissions);
            allOfPermissions = nullToEmpty(allOfPermissions);
            anyOfRoles = nullToEmpty(anyOfRoles);
        }

        private static Set<String> upperCase(Set<String> values) {
            return values == null ? Set.of()
                    : values.stream().map(value -> value.toUpperCase(java.util.Locale.ROOT))
                            .collect(java.util.stream.Collectors.toUnmodifiableSet());
        }

        private static Set<String> nullToEmpty(Set<String> values) {
            return values == null ? Set.of() : Set.copyOf(values);
        }
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
