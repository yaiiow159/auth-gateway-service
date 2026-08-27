package com.example.auth.center.infrastructure.config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * RSA 簽章金鑰設定，支援多把金鑰以完成輪替。
 *
 * <p><b>為什麼需要多把金鑰：</b>金鑰輪替不可能是瞬間完成的原子操作。換上新金鑰的那一刻，
 * 外面還有大量以舊金鑰簽發、尚未過期的 Token。若 JWKS 只發布新公鑰，這些 Token 會在
 * 同一秒內全部驗證失敗 —— 一次例行的金鑰輪替就變成一次全站登出事故。
 * 因此舊公鑰必須繼續發布，直到最後一枚以它簽發的 Token 自然過期為止。
 *
 * <p><b>與 KMS / Vault 的關係：</b>本設定描述的是「應用程式需要什麼」，不是「秘密從哪裡來」。
 * 實務上由 Vault Agent、External Secrets Operator 或 CSI Driver 之類的機制把金鑰材料
 * 投遞到容器內的檔案或環境變數，應用程式再以 {@code file:} 位址讀取。這樣的分工讓
 * 秘密的取得方式可以隨基礎設施演進，而應用程式完全不需要綁定任何一家雲廠商的 SDK。
 * 若確實需要直接呼叫 KMS 簽章（私鑰永不離開 HSM），實作
 * {@link com.example.auth.center.domain.port.RsaKeyProvider} 的另一個 Adapter 即可。
 *
 * @param activeKeyId    目前用於簽章的金鑰識別；留白時取 {@link #keys()} 的第一筆
 * @param reloadInterval 重新讀取金鑰材料的間隔，搭配 Vault Agent 之類的檔案輪替機制使用；
 *                       設為零或負值代表只在啟動時讀取一次
 * @param keys           所有金鑰。已退役但仍需支援驗證的金鑰只要提供公鑰即可
 */
@ConfigurationProperties(prefix = "auth.signing")
public record SigningKeyProperties(String activeKeyId, Duration reloadInterval, List<Key> keys) {

    public SigningKeyProperties {
        reloadInterval = reloadInterval == null ? Duration.ZERO : reloadInterval;
        keys = keys == null ? List.of() : List.copyOf(keys);
    }

    /** 是否有外部提供的金鑰材料；沒有時會退回啟動時產生的臨時金鑰（僅適用單機開發）。 */
    public boolean hasConfiguredKeys() {
        return !keys.isEmpty();
    }

    public boolean reloadEnabled() {
        return !reloadInterval.isZero() && !reloadInterval.isNegative();
    }

    /**
     * 單把金鑰的材料。
     *
     * @param id            寫入 JWT header 的 {@code kid}，驗證方藉此挑選公鑰
     * @param privateKeyPem PKCS#8 私鑰內容，或 {@code classpath:} / {@code file:} 位址。
     *                      已退役的金鑰留白即可 —— 它只需要能驗證，不再需要簽發
     * @param publicKeyPem  X.509 公鑰內容或位址
     */
    public record Key(String id, String privateKeyPem, String publicKeyPem) {

        public Key {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("簽章金鑰必須指定 id，它會成為 JWT 的 kid");
            }
            if (publicKeyPem == null || publicKeyPem.isBlank()) {
                throw new IllegalArgumentException("簽章金鑰必須提供公鑰: kid=" + id);
            }
        }

        public boolean canSign() {
            return privateKeyPem != null && !privateKeyPem.isBlank();
        }
    }
}
