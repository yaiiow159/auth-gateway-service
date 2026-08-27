package com.example.auth.center.application;

import com.example.auth.contract.AuthErrorCode;
import java.util.Objects;

/**
 * 認證流程的業務例外。
 *
 * <p>攜帶 {@link AuthErrorCode} 讓 RestControllerAdvice 能以單一分支轉換成統一的錯誤回應，
 * 不需要為每種失敗情境各寫一個 handler。
 */
public class AuthenticationFailedException extends RuntimeException {

    private final transient AuthErrorCode errorCode;

    public AuthenticationFailedException(AuthErrorCode errorCode) {
        super(errorCode.defaultMessage());
        this.errorCode = Objects.requireNonNull(errorCode);
    }

    public AuthErrorCode errorCode() {
        return errorCode;
    }
}
