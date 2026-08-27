package com.example.auth.center.domain.port;

import java.time.Instant;

/**
 * Access Token 撤銷名單（黑名單）的出口。
 *
 * <p>無狀態 JWT 無法「收回」，因此登出與強制下線必須依賴一份短生命週期的撤銷名單。
 * 名單的 TTL 只需等於 Token 的剩餘壽命 —— 過期之後 Token 本來就無效，紀錄自然可以消失，
 * 這讓黑名單的空間佔用維持在常數級而不會無限膨脹。
 *
 * <p>網關讀取的是同一份 Redis 資料，鍵格式由 {@code auth.token.revocation.key-prefix} 統一約定。
 */
public interface TokenRevocationStore {

    void revoke(String tokenId, Instant tokenExpiresAt);

    boolean isRevoked(String tokenId);
}
