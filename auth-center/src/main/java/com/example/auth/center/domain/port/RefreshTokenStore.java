package com.example.auth.center.domain.port;

import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.token.RefreshToken;
import java.util.Optional;

/** Refresh Token 的儲存出口。 */
public interface RefreshTokenStore {

    /**
     * 簽發一枚 Refresh Token，並將它與同批簽發的 Access Token 綁成同一個工作階段。
     *
     * <p>綁定的用途是登出：客戶端登出時通常只送出 Authorization Header，
     * 若沒有這層對應，伺服端就無從得知該作廢哪一枚 Refresh Token，
     * 只能二選一 —— 放著不管（登出形同虛設），或撤銷該使用者全部裝置的憑證（誤傷其他裝置）。
     *
     * @param sessionId 同批簽發的 Access Token 的 {@code jti}
     */
    RefreshToken issue(UserId userId, String sessionId);

    /**
     * 取出並「同時作廢」一枚 Refresh Token，實作必須保證原子性。
     *
     * <p>這是防止 Refresh Token 重放的關鍵：兩個併發請求只能有一個成功，
     * 因此實作不可以拆成「先讀再刪」兩步。
     *
     * @return 若 Token 不存在或已被使用則回傳 {@link Optional#empty()}
     */
    Optional<RefreshToken> consume(String tokenId);

    /**
     * 依工作階段識別作廢對應的 Refresh Token，供登出使用。
     *
     * @param sessionId Access Token 的 {@code jti}
     * @return 該工作階段沒有對應的 Refresh Token（例如早已被輪替掉）時回傳空值
     */
    Optional<RefreshToken> consumeBySession(String sessionId);

    /**
     * 查出某枚「已被消耗」的 Refresh Token 原本屬於誰。
     *
     * <p>用於偵測重放：合法客戶端手上的 Token 在輪替後就該被丟棄，
     * 同一枚 Token 再次出現代表它極可能已經外洩。此時光是拒絕該次請求並不足夠 ——
     * 真正的攻擊者可能已經先一步換到新的憑證鏈，因此必須知道受害者是誰才能撤銷整條鏈。
     *
     * @return 超過保留期限或從未存在時回傳空值
     */
    Optional<UserId> ownerOfConsumedToken(String tokenId);

    /** 使某使用者所有的 Refresh Token 失效，例如改密碼、偵測到憑證外洩或帳號停權時。 */
    void revokeAll(UserId userId);
}
