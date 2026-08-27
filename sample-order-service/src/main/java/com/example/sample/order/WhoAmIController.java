package com.example.sample.order;

import com.example.auth.client.annotation.CurrentUser;
import com.example.auth.contract.AuthenticatedUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 除錯用端點：直接把服務端解析到的身分回吐出來。
 *
 * <p>用來確認整條鏈（登入 → 網關驗簽 → Header 注入 → 服務端驗章）是否接通。
 */
@RestController
public class WhoAmIController {

    @GetMapping("/orders/whoami")
    public AuthenticatedUser whoAmI(@CurrentUser AuthenticatedUser user) {
        return user;
    }
}
