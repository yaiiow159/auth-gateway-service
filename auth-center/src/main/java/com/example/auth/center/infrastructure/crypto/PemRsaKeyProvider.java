package com.example.auth.center.infrastructure.crypto;

import com.example.auth.center.domain.port.RsaKeyProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 由外部提供的 PEM 金鑰對建立簽章金鑰。
 *
 * <p>PEM 內容應由部署平台的 Secret 機制注入（Kubernetes Secret、Vault Agent 等），
 * 不應該提交進版控。若要接 KMS 或 HSM，實作 {@link RsaKeyProvider} 的另一個 Adapter 即可，
 * 應用層與領域層完全不需要變動。
 */
public class PemRsaKeyProvider implements RsaKeyProvider {

    private static final String PEM_BOUNDARY_PATTERN = "-----(BEGIN|END)[^-]*-----";

    private final RSAKey signingKey;

    public PemRsaKeyProvider(String keyId, String privateKeyPem, String publicKeyPem) {
        RSAPublicKey publicKey = readPublicKey(publicKeyPem);
        RSAPrivateKey privateKey = readPrivateKey(privateKeyPem);
        this.signingKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .build();
    }

    @Override
    public RSAKey signingKey() {
        return signingKey;
    }

    @Override
    public JWKSet publicJwkSet() {
        return new JWKSet(signingKey.toPublicJWK());
    }

    private static RSAPublicKey readPublicKey(String pem) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decode(pem));
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("無法解析 RSA 公鑰，請確認為 X.509 (PEM) 格式", e);
        }
    }

    private static RSAPrivateKey readPrivateKey(String pem) {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decode(pem));
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("無法解析 RSA 私鑰，請確認為 PKCS#8 (PEM) 格式", e);
        }
    }

    private static byte[] decode(String pem) {
        String base64 = pem.replaceAll(PEM_BOUNDARY_PATTERN, "").replaceAll("\s", "");
        return Base64.getDecoder().decode(base64);
    }
}
