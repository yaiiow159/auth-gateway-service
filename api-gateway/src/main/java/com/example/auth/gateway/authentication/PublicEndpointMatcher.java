package com.example.auth.gateway.authentication;

import java.util.List;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * 判斷路徑是否免認證。
 *
 * <p>白名單而非黑名單：漏寫一條白名單只會讓某個公開端點需要登入（會被立刻發現），
 * 漏寫一條黑名單卻會讓需要保護的端點對外裸奔（可能永遠不會被發現）。
 */
public class PublicEndpointMatcher {

    private final List<PathPattern> patterns;

    public PublicEndpointMatcher(List<String> publicPaths) {
        PathPatternParser parser = new PathPatternParser();
        this.patterns = publicPaths.stream().map(parser::parse).toList();
    }

    public boolean isPublic(ServerHttpRequest request) {
        // CORS 預檢請求不會攜帶 Authorization Header，擋下它等於讓所有跨域呼叫失敗
        if (HttpMethod.OPTIONS.equals(request.getMethod())) {
            return true;
        }
        var path = request.getPath().pathWithinApplication();
        return patterns.stream().anyMatch(pattern -> pattern.matches(path));
    }
}
