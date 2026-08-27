package com.example.auth.center.interfaces.rest;

import com.example.auth.center.application.AuthenticationFailedException;
import com.example.auth.center.application.UsernameAlreadyTakenException;
import com.example.auth.center.infrastructure.persistence.RoleNotFoundException;
import com.example.auth.center.infrastructure.persistence.UserNotFoundException;
import com.example.auth.contract.ApiError;
import com.example.auth.contract.AuthErrorCode;
import com.example.auth.contract.AuthHeaders;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
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

    @ExceptionHandler(UsernameAlreadyTakenException.class)
    public ResponseEntity<ApiError> handleUsernameTaken(UsernameAlreadyTakenException e,
                                                        HttpServletRequest request) {
        return toResponse(AuthErrorCode.USERNAME_ALREADY_TAKEN,
                AuthErrorCode.USERNAME_ALREADY_TAKEN.defaultMessage(), request);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiError> handleUserNotFound(UserNotFoundException e, HttpServletRequest request) {
        return toResponse(AuthErrorCode.USER_NOT_FOUND, AuthErrorCode.USER_NOT_FOUND.defaultMessage(), request);
    }

    /** 訊息中包含缺少的角色代碼：這是管理者輸入的內容，回傳它有助於修正而不會洩漏其他資訊。 */
    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ApiError> handleRoleNotFound(RoleNotFoundException e, HttpServletRequest request) {
        return toResponse(AuthErrorCode.ROLE_NOT_FOUND, "指定的角色不存在: " + e.missingRoleCodes(), request);
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

    /**
     * Spring MVC 針對格式錯誤的請求所拋出的例外（壞掉的 JSON、不支援的方法或媒體型別等）
     * 都實作了 {@link ErrorResponse} 並自帶正確的 4xx 狀態碼。
     *
     * <p>少了這個分支，它們會落到下方的兜底處理而被轉成 503：監控看到的是授權中心大量 5xx，
     * 可能觸發告警、讓負載均衡器把健康的實例移出服務、甚至讓上游斷路器跳開，
     * 而實際上只是有人送了壞請求。錯誤的責任歸屬會直接誤導事故排查的方向。
     */
    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            HttpRequestMethodNotSupportedException.class,
            HttpMediaTypeNotSupportedException.class,
            HttpMediaTypeNotAcceptableException.class,
            ServletRequestBindingException.class,
            MethodArgumentTypeMismatchException.class,
            ErrorResponseException.class})
    public ResponseEntity<ApiError> handleClientError(Exception e, HttpServletRequest request) {
        // 這些例外自帶語意正確的狀態碼（400 / 405 / 415 / 406），沿用它而不是一律回 400
        HttpStatusCode status = e instanceof ErrorResponse errorResponse
                ? errorResponse.getStatusCode()
                : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status)
                .body(new ApiError("AUTH-4000", "請求格式不正確",
                        request.getRequestURI(), requestId(request), now()));
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
