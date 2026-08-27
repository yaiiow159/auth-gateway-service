package com.example.sample.order;

import com.example.auth.client.annotation.CurrentUser;
import com.example.auth.client.annotation.RequiresPermission;
import com.example.auth.contract.AuthenticatedUser;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 下游微服務的樣貌：這裡沒有任何一行 Token 解析、簽章驗證或 JWKS 相關的程式碼。
 *
 * <p>服務只認得一件事 —— 一個已經被網關驗證過的 {@link AuthenticatedUser}。
 * 這正是「集中認證、網關校驗、服務明文」想達成的效果：
 * 安全機制的演進（換簽章演算法、加 MFA、改用不透明 Token）不會擴散到業務服務。
 *
 * <p>{@code @RequiresPermission} 與網關的路徑規則重疊是刻意為之的縱深防禦：
 * 網關擋的是外部流量，這一層連內部誤呼叫與繞過網關的直連都能擋。
 */
@RestController
@RequestMapping("/orders")
public class OrderController {

    /** 只需要身分，權限由網關的 order:read 規則把關。 */
    @GetMapping
    public List<Order> myOrders(@CurrentUser AuthenticatedUser user) {
        return List.of(new Order("ORD-1", user.userId(), new BigDecimal("1280.00")));
    }

    @PostMapping
    @RequiresPermission("order:create")
    public Order create(@CurrentUser AuthenticatedUser user) {
        return new Order("ORD-2", user.userId(), new BigDecimal("990.00"));
    }

    /** 需要同時具備兩種權限，示範 {@code requireAll} 的用法。 */
    @DeleteMapping("/{orderId}")
    @RequiresPermission(value = {"order:read", "order:delete"}, requireAll = true)
    public void delete(@PathVariable String orderId, @CurrentUser AuthenticatedUser user) {
        // 真實情境還要確認這張訂單確實屬於這位使用者，那是網關無從得知的資料層授權
    }
}
