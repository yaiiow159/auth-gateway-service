package com.example.auth.gateway.authorization;

/**
 * 單一授權策略的判定結果。
 *
 * <p>{@link #ABSTAIN} 是這個模型的關鍵：它讓每個策略只需回答自己「管得到」的部分，
 * 管不到的就棄權交給下一個策略。沒有棄權語意的話，每個策略都會被迫對全域規則做出判斷，
 * 策略之間就再也無法獨立演進。
 */
public enum AccessDecision {

    /** 明確允許，鏈上後續策略不再評估。 */
    PERMIT,

    /** 明確拒絕，鏈上後續策略不再評估。 */
    DENY,

    /** 本策略不表態，交由下一個策略決定。 */
    ABSTAIN
}
