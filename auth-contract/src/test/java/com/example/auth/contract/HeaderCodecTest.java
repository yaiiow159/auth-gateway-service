package com.example.auth.contract;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class HeaderCodecTest {

    @Test
    @DisplayName("編碼後再解碼可還原原始集合")
    void roundTripsList() {
        Set<String> original = new LinkedHashSet<>(List.of("order:read", "order:create"));

        assertThat(HeaderCodec.decodeList(HeaderCodec.encodeList(original))).isEqualTo(original);
    }

    @Test
    @DisplayName("元素內的分隔符被編碼，不會被誤切成兩個元素")
    void doesNotSplitOnDelimiterInsideElement() {
        Set<String> singleElement = Set.of("ROLE_VIEWER,ROLE_ADMIN");

        String encoded = HeaderCodec.encodeList(singleElement);

        assertThat(encoded).doesNotContain(",").contains("%2C");
        assertThat(HeaderCodec.decodeList(encoded)).containsExactly("ROLE_VIEWER,ROLE_ADMIN");
    }

    @Test
    @DisplayName("控制字元被編碼，不會成為 Header 中的換行")
    void encodesControlCharacters() {
        String encoded = HeaderCodec.encodeValue("ROLE_A\r\nX-Injected: 1");

        assertThat(encoded).doesNotContain("\r").doesNotContain("\n");
        assertThat(HeaderCodec.decodeValue(encoded)).isEqualTo("ROLE_A\r\nX-Injected: 1");
    }

    @Test
    @DisplayName("非 ASCII 內容可正確往返")
    void roundTripsNonAsciiValue() {
        assertThat(HeaderCodec.decodeValue(HeaderCodec.encodeValue("王小明"))).isEqualTo("王小明");
    }

    @Test
    @DisplayName("空值與空白 Header 解碼為空集合")
    void decodesBlankHeaderToEmptySet() {
        assertThat(HeaderCodec.decodeList(null)).isEmpty();
        assertThat(HeaderCodec.decodeList("   ")).isEmpty();
    }
}
