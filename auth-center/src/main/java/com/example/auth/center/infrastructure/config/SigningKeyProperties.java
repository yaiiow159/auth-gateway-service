package com.example.auth.center.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * RSA 簽章金鑰設定。
 *
 * <p>兩者皆留白時，系統會在啟動時產生一組臨時金鑰 —— 僅適用於本機開發，
 * 因為多副本部署下每個副本的金鑰都不同，Token 會無法互相驗證。
 *
 * @param keyId         金鑰識別碼，會寫入 JWT header 的 kid，供金鑰輪替時對應
 * @param privateKeyPem PKCS#8 格式的私鑰內容或 {@code classpath:} / {@code file:} 位址
 * @param publicKeyPem  X.509 格式的公鑰內容或位址
 */
@ConfigurationProperties(prefix = "auth.signing")
public record SigningKeyProperties(String keyId, String privateKeyPem, String publicKeyPem) {

    public SigningKeyProperties {
        keyId = keyId == null || keyId.isBlank() ? "auth-center-key" : keyId;
    }

    public boolean hasStaticKeyPair() {
        return isPresent(privateKeyPem) && isPresent(publicKeyPem);
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }
}
