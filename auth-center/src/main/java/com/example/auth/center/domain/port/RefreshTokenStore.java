package com.example.auth.center.domain.port;

import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.token.RefreshToken;
import java.util.Optional;

/** Refresh Token 的儲存出口。 */
public interface RefreshTokenStore {

    RefreshToken issue(UserId userId);

    /**
     * 取出並「同時作廢」一枚 Refresh Token，實作必須保證原子性。
     *
     * <p>這是防止 Refresh Token 重放的關鍵：兩個併發請求只能有一個成功，
     * 因此實作不可以拆成「先讀再刪」兩步。
     *
     * @return 若 Token 不存在或已被使用則回傳 {@link Optional#empty()}
     */
    Optional<RefreshToken> consume(String tokenId);

    /** 使某使用者所有的 Refresh Token 失效，例如改密碼或偵測到憑證外洩時。 */
    void revokeAll(UserId userId);
}
