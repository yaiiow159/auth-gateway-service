package com.example.auth.client.web;

import com.example.auth.client.context.ForbiddenException;
import com.example.auth.client.context.MissingIdentityException;
import com.example.auth.contract.ApiError;
import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthHeaders;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 把身分與權限相關的例外轉成與網關、授權中心完全一致的錯誤格式。
 *
 * <p>一致性的實際價值：前端只要寫一份錯誤處理，就能同時應付「被網關擋下」與
 * 「被服務內部擋下」兩種情況，不必去分辨錯誤是從哪一層來的。
 */
@RestControllerAdvice
public class AuthClientExceptionHandler {

    private final Clock clock;

    public AuthClientExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(MissingIdentityException.class)
    public ResponseEntity<ApiError> handleMissingIdentity(MissingIdentityException e, HttpServletRequest request) {
        return toResponse(AuthErrorCode.TOKEN_MISSING, request);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<ApiError> handleForbidden(ForbiddenException e, HttpServletRequest request) {
        return toResponse(AuthErrorCode.ACCESS_DENIED, request);
    }

    private ResponseEntity<ApiError> toResponse(AuthErrorCode errorCode, HttpServletRequest request) {
        ApiError body = ApiError.of(errorCode, request.getRequestURI(),
                request.getHeader(AuthHeaders.REQUEST_ID), Instant.now(clock));
        return ResponseEntity.status(errorCode.httpStatus()).body(body);
    }
}
