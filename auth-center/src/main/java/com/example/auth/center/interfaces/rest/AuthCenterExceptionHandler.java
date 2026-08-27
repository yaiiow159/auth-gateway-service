package com.example.auth.center.interfaces.rest;

import com.example.auth.center.application.AuthenticationFailedException;
import com.example.auth.contract.ApiError;
import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthHeaders;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全域錯誤轉換。
 *
 * <p>集中在一處的價值在於：所有對外的錯誤格式必然一致，而且「不要把內部例外訊息吐給客戶端」
 * 這條安全規則只需要在這裡守住一次。
 */
@RestControllerAdvice
public class AuthCenterExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthCenterExceptionHandler.class);

    private final Clock clock;

    public AuthCenterExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ApiError> handleAuthenticationFailed(AuthenticationFailedException e,
                                                               HttpServletRequest request) {
        return toResponse(e.errorCode(), e.errorCode().defaultMessage(), request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationFailure(MethodArgumentNotValidException e,
                                                            HttpServletRequest request) {
        String detail = e.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(error -> error.getField() + " " + error.getDefaultMessage())
                .orElse("請求參數不正確");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiError("AUTH-4000", detail, request.getRequestURI(), requestId(request), now()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception e, HttpServletRequest request) {
        // 未預期的例外要留完整堆疊在伺服端，但對外只回傳一句無資訊量的訊息
        log.error("未預期的錯誤: path={}", request.getRequestURI(), e);
        return toResponse(AuthErrorCode.AUTH_CENTER_UNAVAILABLE,
                AuthErrorCode.AUTH_CENTER_UNAVAILABLE.defaultMessage(), request);
    }

    private ResponseEntity<ApiError> toResponse(AuthErrorCode errorCode, String message, HttpServletRequest request) {
        return ResponseEntity.status(errorCode.httpStatus())
                .body(ApiError.of(errorCode, message, request.getRequestURI(), requestId(request), now()));
    }

    private static String requestId(HttpServletRequest request) {
        return request.getHeader(AuthHeaders.REQUEST_ID);
    }

    private Instant now() {
        return Instant.now(clock);
    }
}
