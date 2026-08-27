package com.example.auth.center.domain.port;

import com.nimbusds.jose.jwk.RSAKey;

/**
 * 簽章金鑰的來源。
 *
 * <p>開發環境用啟動時隨機產生的金鑰即可；正式環境應由 KMS / Vault / HSM 提供，
 * 並支援金鑰輪替 —— 因此 {@link #signingKey()} 與 {@link #publicJwkSet()} 分開定義：
 * 輪替期間 JWKS 必須同時發布新舊公鑰，讓仍在有效期內的舊 Token 還能被驗證。
 */
public interface RsaKeyProvider {

    /** 目前用於簽章的金鑰（含私鑰），其 {@code kid} 會寫入 JWT header。 */
    RSAKey signingKey();

    /** 對外發布的公鑰集合，可能包含尚未淘汰的舊金鑰。 */
    com.nimbusds.jose.jwk.JWKSet publicJwkSet();
}
