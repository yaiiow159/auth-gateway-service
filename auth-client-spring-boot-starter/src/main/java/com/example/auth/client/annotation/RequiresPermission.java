package com.example.auth.client.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 方法層級的細粒度權限檢查。
 *
 * <p>與網關的路徑規則是縱深防禦的兩層：網關擋掉「這個角色根本不該碰這條路由」，
 * 這裡則負責網關看不到的細節。萬一某天有人繞過網關直連服務，這一層仍然守得住。
 *
 * <p>把權限宣告寫在方法簽章旁邊，也讓「這支 API 需要什麼權限」成為程式碼的一部分，
 * 而不是散落在另一份會過期的設定檔或文件裡。
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresPermission {

    /** 需要的權限碼。 */
    String[] value();

    /** 為 {@code true} 時必須同時具備所有權限，否則具備任一即可。 */
    boolean requireAll() default false;
}
