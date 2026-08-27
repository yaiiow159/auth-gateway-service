package com.example.auth.contract;

import java.time.Instant;

/**
 * 全系統統一的錯誤回應格式。
 *
 * <p>網關、授權中心與各微服務共用同一個 record，前端因此只需要處理一種錯誤結構。
 * 這種一致性在服務數量成長後的價值遠大於它的實作成本。
 *
 * @param code      機器可讀的錯誤碼，見 {@link AuthErrorCode}
 * @param message   給人看的描述，不應包含任何內部細節或堆疊資訊
 * @param path      發生錯誤的請求路徑
 * @param requestId 全鏈路追蹤識別碼，客訴時用它就能直接撈出對應日誌
 * @param timestamp 發生時間
 */
public record ApiError(String code, String message, String path, String requestId, Instant timestamp) {

    public static ApiError of(AuthErrorCode errorCode, String path, String requestId, Instant timestamp) {
        return new ApiError(errorCode.code(), errorCode.defaultMessage(), path, requestId, timestamp);
    }

    public static ApiError of(AuthErrorCode errorCode, String message, String path, String requestId,
                              Instant timestamp) {
        return new ApiError(errorCode.code(), message, path, requestId, timestamp);
    }
}
