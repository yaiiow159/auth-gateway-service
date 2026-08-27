package com.example.auth.contract;

/**
 * JWT 自訂 Claim 名稱。
 *
 * <p>刻意使用短名稱以壓縮 Token 體積 —— Token 會出現在每一個請求的 Header 上，
 * 每省下一個位元組都會乘上 QPS。
 */
public final class ClaimNames {

    /** 使用者名稱。 */
    public static final String USERNAME = "unm";
    /** 角色清單（JSON array）。 */
    public static final String ROLES = "rol";
    /** 權限碼清單（JSON array）。 */
    public static final String PERMISSIONS = "prm";
    /** 租戶識別碼。 */
    public static final String TENANT_ID = "tid";
    /** Token 類型，值為 {@link #TYPE_ACCESS} 或 {@link #TYPE_REFRESH}。 */
    public static final String TOKEN_TYPE = "typ";

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private ClaimNames() {
        throw new AssertionError("常數類別不應被實例化");
    }
}
