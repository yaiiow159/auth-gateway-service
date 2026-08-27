package com.example.auth.client.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 將網關注入的身分直接綁定到 Controller 參數。
 *
 * <pre>{@code
 * @GetMapping("/orders")
 * public List<Order> myOrders(@CurrentUser AuthenticatedUser user) { ... }
 * }</pre>
 *
 * <p>比起讓每個 Controller 各自去讀 {@code X-User-Id} Header，這個註解把
 * 「身分從哪裡來、怎麼驗證」完全隱藏起來 —— 日後改用 mTLS 或 Service Mesh 傳遞身分，
 * 業務程式碼不需要有任何改動。
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentUser {

    /** 為 {@code false} 時，匿名請求會得到 {@code null} 而不是被拒絕。 */
    boolean required() default true;
}
