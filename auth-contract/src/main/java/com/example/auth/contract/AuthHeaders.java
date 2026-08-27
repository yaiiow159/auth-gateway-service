package com.example.auth.contract;

import java.util.List;

/**
 * 網關注入給下游微服務的身分 Header 契約。
 *
 * <p><b>安全前提：</b>這些 Header 只能由網關產生。網關在注入前必須先移除
 * {@link #CLIENT_FORGEABLE} 中所有由客戶端帶進來的同名 Header，否則任何人
 * 都能自行送出 {@code X-User-Id: 1} 來冒充管理員。
 */
public final class AuthHeaders {

    /** 使用者唯一識別碼。 */
    public static final String USER_ID = "X-User-Id";
    /** 使用者登入帳號，僅供下游記錄稽核日誌使用。 */
    public static final String USERNAME = "X-User-Name";
    /** 角色清單，以 {@link #VALUE_DELIMITER} 分隔。 */
    public static final String ROLES = "X-User-Roles";
    /** 權限碼清單，以 {@link #VALUE_DELIMITER} 分隔。 */
    public static final String PERMISSIONS = "X-User-Permissions";
    /** 多租戶識別碼。 */
    public static final String TENANT_ID = "X-Tenant-Id";
    /** 網關對上述身分內容所做的 HMAC 簽章，格式見 {@link IdentitySignatures}。 */
    public static final String SIGNATURE = "X-Auth-Signature";
    /** 全鏈路追蹤用的請求識別碼。 */
    public static final String REQUEST_ID = "X-Request-Id";

    /** 多值 Header 的分隔符號。 */
    public static final String VALUE_DELIMITER = ",";

    /**
     * 所有「客戶端可能偽造、網關必須無條件剝除」的 Header。
     * 新增身分 Header 時務必同步加入此清單。
     */
    public static final List<String> CLIENT_FORGEABLE =
            List.of(USER_ID, USERNAME, ROLES, PERMISSIONS, TENANT_ID, SIGNATURE);

    private AuthHeaders() {
        throw new AssertionError("常數類別不應被實例化");
    }
}
