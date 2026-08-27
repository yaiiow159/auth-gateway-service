package com.example.auth.center.infrastructure.crypto;

import com.example.auth.center.domain.port.RsaKeyProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 啟動時產生一組臨時 RSA 金鑰，供本機開發使用。
 *
 * <p>正式環境請改用 {@link RotatingRsaKeyProvider}：
 * 這個實作在多副本部署下每個副本持有不同私鑰，A 副本簽的 Token 到 B 副本就驗不過。
 */
public class InMemoryRsaKeyProvider implements RsaKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(InMemoryRsaKeyProvider.class);
    private static final int KEY_SIZE = 2048;

    private final RSAKey signingKey;

    public InMemoryRsaKeyProvider(String keyId) {
        this.signingKey = generate(keyId);
        log.warn("使用啟動時產生的臨時簽章金鑰 (kid={})，僅適用於開發環境；"
                + "正式環境請設定 auth.signing.keys 由外部注入金鑰材料", keyId);
    }

    @Override
    public RSAKey signingKey() {
        return signingKey;
    }

    @Override
    public JWKSet publicJwkSet() {
        return new JWKSet(signingKey.toPublicJWK());
    }

    private static RSAKey generate(String keyId) {
        try {
            return new RSAKeyGenerator(KEY_SIZE).keyID(keyId).keyUse(KeyUse.SIGNATURE).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("無法產生 RSA 簽章金鑰", e);
        }
    }
}
