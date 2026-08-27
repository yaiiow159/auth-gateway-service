package com.example.auth.client.context;

import com.example.auth.contract.AuthenticatedUser;
import java.util.Optional;

/**
 * 目前請求的身分持有者。
 *
 * <p>提供給無法透過方法參數取得身分的地方使用（Service 深處、AOP、稽核日誌）。
 * 業務程式碼應優先使用 {@code @CurrentUser} 參數注入 —— 顯式傳遞比隱式讀取更容易測試，
 * ThreadLocal 是不得已時的補充，不是預設選項。
 *
 * <p>{@link #clear()} 必須在 Filter 的 {@code finally} 區塊中呼叫。執行緒池會重用執行緒，
 * 忘記清除等於讓下一個請求繼承上一個使用者的身分，這是嚴重的資安事故。
 */
public final class UserContextHolder {

    private static final ThreadLocal<AuthenticatedUser> CURRENT_USER = new ThreadLocal<>();

    private UserContextHolder() {
        throw new AssertionError("工具類別不應被實例化");
    }

    public static void set(AuthenticatedUser user) {
        CURRENT_USER.set(user);
    }

    public static Optional<AuthenticatedUser> get() {
        return Optional.ofNullable(CURRENT_USER.get());
    }

    /** 取得身分，匿名時拋出例外；適用於「到這裡就一定該有身分」的呼叫點。 */
    public static AuthenticatedUser require() {
        return get().orElseThrow(() -> new MissingIdentityException("目前請求沒有已認證的身分"));
    }

    public static void clear() {
        CURRENT_USER.remove();
    }
}
