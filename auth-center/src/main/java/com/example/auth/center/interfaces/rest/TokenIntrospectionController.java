package com.example.auth.center.interfaces.rest;

import com.example.auth.center.application.TokenIntrospectionService;
import com.example.auth.center.interfaces.rest.dto.IntrospectionRequest;
import com.example.auth.center.interfaces.rest.dto.IntrospectionResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 內部 Token 自省端點。
 *
 * <p>路徑前綴 {@code /internal} 是一個約定：網關不會把這類路徑對外開放，
 * 只有叢集內部元件能呼叫。這條規則由網關的路由設定強制執行，而非靠自律。
 */
@RestController
@RequestMapping("/internal/tokens")
public class TokenIntrospectionController {

    private final TokenIntrospectionService introspectionService;

    public TokenIntrospectionController(TokenIntrospectionService introspectionService) {
        this.introspectionService = introspectionService;
    }

    @PostMapping("/introspect")
    public IntrospectionResponse introspect(@Valid @RequestBody IntrospectionRequest request) {
        return introspectionService.introspect(request.token())
                .map(IntrospectionResponse::active)
                .orElseGet(IntrospectionResponse::inactive);
    }
}
