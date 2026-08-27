package com.example.auth.gateway.identity;

import com.example.auth.contract.AuthenticatedUser;
import com.example.auth.contract.IdentitySignatures;
import java.time.Instant;
import java.util.Optional;

/**
 * 身分簽章策略：「要不要簽」與「用什麼密鑰簽」是一組不可分割的決定。
 *
 * <p>把這兩者綁成一個型別，「啟用簽章卻沒有密鑰」就從一個需要被檢查的錯誤狀態，
 * 變成一個根本無法被表達的狀態 —— 不變條件由型別自己保證，而不是散落在各個使用端。
 *
 * <p>它同時承擔簽章的執行（{@link #signatureFor}），而不只是攜帶設定值。
 * 因此 {@link IdentityPropagator} 不需要認識 {@link IdentitySignatures}，
 * 也不需要為了決定要不要簽而讀取一個布林旗標。
 *
 * <p>注意這裡不包含簽章的有效期間：簽章方只負責蓋上時間戳，
 * 「多久以內的簽章還算數」是驗章方（下游服務的 {@code auth.client.signature-ttl}）
 * 的風險決策，把它放在這裡只會變成一個不會生效的設定。
 */
public record IdentitySigningPolicy(boolean enabled, String secret) {

    public IdentitySigningPolicy {
        if (enabled && (secret == null || secret.isBlank())) {
            throw new IllegalArgumentException(
                    "已啟用身分簽章但未設定 gateway.auth.identity.signing-secret；"
                            + "請由環境變數或 Secret 注入，切勿寫死在設定檔中");
        }
    }

    /** 不對注入的身分簽章。僅適用於網路層能百分之百保證只有網關碰得到下游服務的部署。 */
    public static IdentitySigningPolicy disabled() {
        return new IdentitySigningPolicy(false, null);
    }

    /** 以共享密鑰簽章，密鑰須與下游服務的 {@code auth.client.signing-secret} 相同。 */
    public static IdentitySigningPolicy signingWith(String secret) {
        return new IdentitySigningPolicy(true, secret);
    }

    /**
     * 為指定身分產生簽章。
     *
     * @return 未啟用簽章時回傳 {@link Optional#empty()}
     */
    public Optional<String> signatureFor(AuthenticatedUser user, Instant issuedAt) {
        return enabled
                ? Optional.of(IdentitySignatures.sign(secret, user, issuedAt))
                : Optional.empty();
    }
}
