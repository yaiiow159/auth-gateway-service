package com.example.auth.gateway.authorization;

/**
 * 授權策略。
 *
 * <p>要新增一種授權模型（ABAC 屬性判斷、時段限制、IP 白名單……），
 * 只需要實作這個介面並註冊成 Bean，既有的策略與過濾器一行都不用改 —— 開放封閉原則。
 */
public interface AccessPolicy {

    AccessDecision evaluate(AccessContext context);

    /** 數值越小越先評估。 */
    default int order() {
        return 0;
    }

    /** 出現在日誌中的策略名稱，用來說明請求是被哪一條策略擋下的。 */
    default String name() {
        return getClass().getSimpleName();
    }
}
