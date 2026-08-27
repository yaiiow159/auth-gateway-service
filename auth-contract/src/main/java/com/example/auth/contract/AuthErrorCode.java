package com.example.auth.contract;

/**
 * 認證與授權的錯誤碼。
 *
 * <p>網關與 Auth Center 共用同一組錯誤碼，讓前端只需要維護一份錯誤處理邏輯；
 * 錯誤訊息本身刻意保持模糊（例如不區分「帳號不存在」與「密碼錯誤」），
 * 避免成為帳號列舉（account enumeration）的側信道。
 */
public enum AuthErrorCode {

    TOKEN_MISSING("AUTH-1001", 401, "缺少存取憑證"),
    TOKEN_INVALID("AUTH-1002", 401, "存取憑證無效"),
    TOKEN_EXPIRED("AUTH-1003", 401, "存取憑證已過期"),
    TOKEN_REVOKED("AUTH-1004", 401, "存取憑證已被撤銷"),
    CREDENTIALS_INVALID("AUTH-1005", 401, "帳號或密碼錯誤"),
    ACCOUNT_DISABLED("AUTH-1006", 403, "帳號已被停用"),
    IDENTITY_SIGNATURE_INVALID("AUTH-1007", 401, "身分簽章驗證失敗"),

    ACCESS_DENIED("AUTH-2001", 403, "權限不足"),

    RATE_LIMITED("AUTH-3001", 429, "請求過於頻繁"),

    AUTH_CENTER_UNAVAILABLE("AUTH-9001", 503, "認證服務暫時無法使用");

    private final String code;
    private final int httpStatus;
    private final String defaultMessage;

    AuthErrorCode(String code, int httpStatus, String defaultMessage) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public String code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
