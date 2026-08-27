package com.example.auth.gateway.authentication;

import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthenticatedUser;

/**
 * 認證結果的代數資料型別。
 *
 * <p>用 sealed interface 表達「成功或失敗，沒有第三種可能」，呼叫端以 switch 模式比對處理時，
 * 編譯器會保證所有分支都被涵蓋。相較於「回傳可能為 null 的使用者」或「以例外表達失敗」，
 * 這種寫法把可能的狀態顯性寫進型別裡，維護者不需要讀完實作才知道有哪些情況要處理。
 */
public sealed interface AuthenticationResult {

    /**
     * 認證成功。
     *
     * @param tokenId Token 的 {@code jti}，供撤銷檢查與稽核日誌使用
     */
    record Success(AuthenticatedUser user, String tokenId) implements AuthenticationResult {
    }

    /**
     * 認證失敗。
     *
     * @param detail 僅供伺服端日誌使用，不應原封不動回傳給客戶端
     */
    record Failure(AuthErrorCode errorCode, String detail) implements AuthenticationResult {
    }

    static AuthenticationResult success(AuthenticatedUser user, String tokenId) {
        return new Success(user, tokenId);
    }

    static AuthenticationResult failure(AuthErrorCode errorCode, String detail) {
        return new Failure(errorCode, detail);
    }
}
