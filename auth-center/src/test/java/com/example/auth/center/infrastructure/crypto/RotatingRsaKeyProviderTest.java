package com.example.auth.center.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.center.infrastructure.config.SigningKeyProperties;
import com.nimbusds.jose.jwk.JWK;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RotatingRsaKeyProviderTest {

    private static KeyPair currentPair;
    private static KeyPair retiredPair;
    private static KeyPair replacementPair;

    /** 產生金鑰是昂貴運算，整個測試類別共用同一組即可。 */
    @BeforeAll
    static void generateKeyPairs() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        currentPair = generator.generateKeyPair();
        retiredPair = generator.generateKeyPair();
        replacementPair = generator.generateKeyPair();
    }

    @Test
    @DisplayName("以 active-key-id 指定的金鑰簽章，但 JWKS 發布全部公鑰")
    void signsWithActiveKeyWhilePublishingEveryPublicKey() {
        Map<String, String> material = new HashMap<>();
        SigningKeyProperties properties = new SigningKeyProperties("current", Duration.ZERO, List.of(
                keyOf(material, "retired", retiredPair, false),
                keyOf(material, "current", currentPair, true)));

        RotatingRsaKeyProvider provider = new RotatingRsaKeyProvider(properties, material::get);

        assertThat(provider.signingKey().getKeyID()).isEqualTo("current");
        assertThat(provider.publicJwkSet().getKeys()).extracting(JWK::getKeyID)
                .containsExactlyInAnyOrder("retired", "current");
    }

    @Test
    @DisplayName("JWKS 不得洩漏私鑰")
    void neverPublishesPrivateKeyMaterial() {
        Map<String, String> material = new HashMap<>();
        SigningKeyProperties properties = new SigningKeyProperties(null, Duration.ZERO, List.of(
                keyOf(material, "current", currentPair, true)));

        RotatingRsaKeyProvider provider = new RotatingRsaKeyProvider(properties, material::get);

        assertThat(provider.publicJwkSet().getKeys()).allSatisfy(key -> assertThat(key.isPrivate()).isFalse());
        assertThat(provider.signingKey().isPrivate()).isTrue();
    }

    @Test
    @DisplayName("未指定 active-key-id 時取第一把附帶私鑰的金鑰")
    void fallsBackToFirstSignableKey() {
        Map<String, String> material = new HashMap<>();
        SigningKeyProperties properties = new SigningKeyProperties(null, Duration.ZERO, List.of(
                keyOf(material, "retired", retiredPair, false),
                keyOf(material, "current", currentPair, true)));

        RotatingRsaKeyProvider provider = new RotatingRsaKeyProvider(properties, material::get);

        assertThat(provider.signingKey().getKeyID()).isEqualTo("current");
    }

    @Test
    @DisplayName("指定的簽章金鑰缺少私鑰時啟動即失敗，而非在第一次簽發時才爆炸")
    void failsFastWhenActiveKeyCannotSign() {
        Map<String, String> material = new HashMap<>();
        SigningKeyProperties properties = new SigningKeyProperties("retired", Duration.ZERO, List.of(
                keyOf(material, "retired", retiredPair, false)));

        assertThatThrownBy(() -> new RotatingRsaKeyProvider(properties, material::get))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("retired");
    }

    @Test
    @DisplayName("金鑰材料被就地改寫後，reload 會換上新金鑰")
    void picksUpRotatedMaterialOnReload() {
        Map<String, String> material = new HashMap<>();
        SigningKeyProperties properties = new SigningKeyProperties("current", Duration.ofMinutes(1), List.of(
                keyOf(material, "current", currentPair, true)));
        RotatingRsaKeyProvider provider = new RotatingRsaKeyProvider(properties, material::get);
        String originalModulus = provider.signingKey().getModulus().toString();

        // 模擬 Vault Agent 就地改寫同一個檔案
        material.put("current.key", pem(replacementPair.getPrivate().getEncoded()));
        material.put("current.pub", pem(replacementPair.getPublic().getEncoded()));
        provider.reload();

        assertThat(provider.signingKey().getModulus().toString()).isNotEqualTo(originalModulus);
        assertThat(provider.signingKey().getKeyID()).isEqualTo("current");
    }

    @Test
    @DisplayName("重載失敗時沿用既有金鑰，不讓服務因秘密投遞的短暫異常而中斷")
    void keepsExistingKeysWhenReloadFails() {
        Map<String, String> material = new HashMap<>();
        SigningKeyProperties properties = new SigningKeyProperties("current", Duration.ofMinutes(1), List.of(
                keyOf(material, "current", currentPair, true)));
        RotatingRsaKeyProvider provider = new RotatingRsaKeyProvider(properties, material::get);
        String originalModulus = provider.signingKey().getModulus().toString();

        material.put("current.key", "這不是一份合法的 PEM");
        provider.reload();

        assertThat(provider.signingKey().getModulus().toString()).isEqualTo(originalModulus);
    }

    private static SigningKeyProperties.Key keyOf(Map<String, String> material, String id,
                                                  KeyPair pair, boolean withPrivateKey) {
        material.put(id + ".pub", pem(pair.getPublic().getEncoded()));
        if (withPrivateKey) {
            material.put(id + ".key", pem(pair.getPrivate().getEncoded()));
        }
        return new SigningKeyProperties.Key(id, withPrivateKey ? id + ".key" : null, id + ".pub");
    }

    private static String pem(byte[] encoded) {
        return Base64.getMimeEncoder().encodeToString(encoded);
    }
}
