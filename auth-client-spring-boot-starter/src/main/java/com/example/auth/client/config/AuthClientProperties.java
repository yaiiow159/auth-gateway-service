package com.example.auth.client.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 下游服務端的身分解析設定。
 *
 * @param verifySignature 是否驗證網關的 HMAC 簽章。設為 {@code false} 等於無條件相信
 *                        任何送進來的 {@code X-User-Id}，只有在網路層能百分之百保證
 *                        「除了網關沒有人碰得到這個服務」時才可接受
 * @param signingSecret   與網關共享的密鑰
 * @param signatureTtl    允許的簽章時間偏差，需與網關設定一致
 */
@ConfigurationProperties(prefix = "auth.client")
public record AuthClientProperties(Boolean verifySignature, String signingSecret, Duration signatureTtl) {

    public AuthClientProperties {
        verifySignature = verifySignature == null || verifySignature;
        signatureTtl = signatureTtl == null ? Duration.ofSeconds(60) : signatureTtl;
    }
}
