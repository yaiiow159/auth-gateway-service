package com.example.auth.center.infrastructure.crypto;

import com.example.auth.center.domain.port.RsaKeyProvider;
import com.example.auth.center.infrastructure.config.SigningKeyProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.List;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 支援輪替的金鑰來源：以指定的金鑰簽章，同時發布全部公鑰供驗證。
 *
 * <p>輪替的完整流程分成三步，本類別讓每一步都不需要停機：
 * <ol>
 *   <li><b>準備：</b>把新金鑰加入 {@code keys}，但 {@code active-key-id} 仍指向舊金鑰。
 *       新公鑰立刻出現在 JWKS 中，讓所有驗證方有時間抓取。</li>
 *   <li><b>切換：</b>將 {@code active-key-id} 改為新金鑰。此後簽發的 Token 使用新金鑰，
 *       而舊公鑰仍在 JWKS 中，既有 Token 不受影響。</li>
 *   <li><b>退役：</b>等最後一枚以舊金鑰簽發的 Token 過期後（至少一個 Access Token 的壽命），
 *       才把舊金鑰從設定中移除。</li>
 * </ol>
 * 少了第一步或第三步，輪替就會變成一次全站的驗證失敗。
 *
 * <p>{@link #reload()} 讓金鑰材料可以在不重啟的情況下更新，對應 Vault Agent 之類
 * 定期改寫檔案的秘密投遞機制。內部狀態以單一 {@code volatile} 參考整批替換，
 * 因此讀取端永遠看到的是一組完整而一致的金鑰，不會撞見替換到一半的中間狀態。
 */
public class RotatingRsaKeyProvider implements RsaKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(RotatingRsaKeyProvider.class);

    private final SigningKeyProperties properties;
    private final UnaryOperator<String> materialResolver;

    private volatile KeySet current;

    /**
     * @param materialResolver 將設定值（可能是 PEM 內容，也可能是 {@code file:} 位址）解析為實際內容
     */
    public RotatingRsaKeyProvider(SigningKeyProperties properties, UnaryOperator<String> materialResolver) {
        this.properties = properties;
        this.materialResolver = materialResolver;
        this.current = load();
        log.info("載入簽章金鑰: active={}, 共 {} 把", current.signingKey().getKeyID(), current.all().size());
    }

    @Override
    public RSAKey signingKey() {
        return current.signingKey();
    }

    @Override
    public JWKSet publicJwkSet() {
        return current.publicJwkSet();
    }

    /**
     * 重新讀取金鑰材料。
     *
     * <p>刻意在讀取失敗時保留既有金鑰而非讓應用程式崩潰：秘密投遞機制在改寫檔案的瞬間
     * 可能出現短暫的不一致，為此中斷一個原本運作正常的服務並不划算。失敗會留下錯誤日誌供告警。
     */
    public void reload() {
        try {
            KeySet reloaded = load();
            if (reloaded.equals(current)) {
                return;
            }
            current = reloaded;
            log.info("簽章金鑰已更新: active={}, 共 {} 把",
                    reloaded.signingKey().getKeyID(), reloaded.all().size());
        } catch (RuntimeException e) {
            log.error("重新載入簽章金鑰失敗，沿用既有金鑰", e);
        }
    }

    private KeySet load() {
        List<RSAKey> keys = properties.keys().stream()
                .map(this::toRsaKey)
                .toList();
        return new KeySet(keys, resolveSigningKey(keys));
    }

    private RSAKey toRsaKey(SigningKeyProperties.Key key) {
        return RsaKeys.parse(
                key.id(),
                key.canSign() ? materialResolver.apply(key.privateKeyPem()) : null,
                materialResolver.apply(key.publicKeyPem()));
    }

    /** 未指定 active-key-id 時取第一把具備私鑰的金鑰，讓單金鑰的常見情境不必額外設定。 */
    private RSAKey resolveSigningKey(List<RSAKey> keys) {
        String activeKeyId = properties.activeKeyId();
        return keys.stream()
                .filter(key -> key.isPrivate()
                        && (activeKeyId == null || activeKeyId.isBlank() || activeKeyId.equals(key.getKeyID())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(activeKeyId == null || activeKeyId.isBlank()
                        ? "auth.signing.keys 中沒有任何一把附帶私鑰的金鑰，無法簽發 Token"
                        : "找不到可簽章的金鑰或該金鑰缺少私鑰: auth.signing.active-key-id=" + activeKeyId));
    }

    /** 一組一致的金鑰快照，整批替換以避免讀取到中間狀態。 */
    private record KeySet(List<RSAKey> all, RSAKey signingKey) {

        JWKSet publicJwkSet() {
            return new JWKSet(all.stream().map(key -> (JWK) key.toPublicJWK()).toList());
        }
    }
}
