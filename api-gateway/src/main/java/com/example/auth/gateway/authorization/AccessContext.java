package com.example.auth.gateway.authorization;

import com.example.auth.contract.AuthenticatedUser;
import java.util.Objects;

/**
 * 授權判定的輸入。
 *
 * <p>刻意不直接傳入 {@code ServerWebExchange}：策略只需要「誰、要對哪條路徑、做什麼動作」，
 * 讓它依賴整個 HTTP 交換物件會使單元測試被迫組裝一堆無關的框架物件。
 *
 * @param path   請求路徑（不含 query string）
 * @param method HTTP 方法，大寫
 * @param user   已認證的使用者
 */
public record AccessContext(String path, String method, AuthenticatedUser user) {

    public AccessContext {
        Objects.requireNonNull(path, "path 不可為 null");
        Objects.requireNonNull(method, "method 不可為 null");
        Objects.requireNonNull(user, "user 不可為 null");
    }
}
