package com.example.auth.center.interfaces.rest;

/** Authorization Header 的解析工具。 */
final class BearerTokens {

    private static final String PREFIX = "Bearer ";

    private BearerTokens() {
    }

    /** 從 Authorization Header 取出 Token，格式不符時回傳空字串而非拋錯。 */
    static String extract(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            return "";
        }
        return authorizationHeader.substring(PREFIX.length()).trim();
    }
}
