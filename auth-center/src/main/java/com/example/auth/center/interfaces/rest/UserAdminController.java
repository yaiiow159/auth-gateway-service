package com.example.auth.center.interfaces.rest;

import com.example.auth.center.application.CreateUserCommand;
import com.example.auth.center.application.UserProvisioningService;
import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.interfaces.rest.dto.ChangePasswordRequest;
import com.example.auth.center.interfaces.rest.dto.ChangeStatusRequest;
import com.example.auth.center.interfaces.rest.dto.CreateUserRequest;
import com.example.auth.center.interfaces.rest.dto.ReplaceRolesRequest;
import com.example.auth.center.interfaces.rest.dto.UserResponse;
import com.example.auth.client.annotation.CurrentUser;
import com.example.auth.client.annotation.RequiresPermission;
import com.example.auth.contract.AuthenticatedUser;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * 使用者與角色的管理端點。
 *
 * <p><b>授權中心在這裡沒有特權。</b>這些端點與其他微服務的端點一樣位於網關之後，
 * 消費網關注入的身分，並以 {@code @RequiresPermission} 做細粒度檢查。
 * 讓授權中心自己也走一遍完整的授權流程，是驗證整套模型是否真的可用的最好方式 ——
 * 如果連它自己都得繞過，那這套模型就有問題。
 *
 * <p>路徑不掛在 {@code /internal} 之下，因為它需要由真人透過網關存取；
 * 網關以 {@code /api/admin/**} 對外路由，並要求 {@code user:manage} 權限。
 *
 * <p>每個操作都記錄「誰對誰做了什麼」。權限異動是稽核的重點對象，
 * 少了操作者的身分，事後追查只能看到帳號被改了卻不知道是誰改的。
 *
 * <p>權限標註逐一寫在方法上而非類別上：{@code @RequiresPermission} 的切點比對的是
 * 方法註解，標在類別上不會生效。逐一標註雖然囉嗦，但「漏標就沒有保護」這件事
 * 至少是看得見的 —— 網關的路徑規則則是同一道防線的另一層。
 */
@RestController
@RequestMapping("/admin/users")
public class UserAdminController {

    private static final Logger log = LoggerFactory.getLogger(UserAdminController.class);

    private final UserProvisioningService userProvisioningService;

    public UserAdminController(UserProvisioningService userProvisioningService) {
        this.userProvisioningService = userProvisioningService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission("user:manage")
    public UserResponse create(@Valid @RequestBody CreateUserRequest request,
                               @CurrentUser AuthenticatedUser operator) {
        audit(operator, "建立帳號", request.username());
        return UserResponse.from(userProvisioningService.createUser(new CreateUserCommand(
                request.username(), request.password(), request.tenantId(), request.roleCodes())));
    }

    @PutMapping("/{userId}/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @RequiresPermission("user:manage")
    public void changePassword(@PathVariable String userId,
                               @Valid @RequestBody ChangePasswordRequest request,
                               @CurrentUser AuthenticatedUser operator) {
        audit(operator, "變更密碼", userId);
        userProvisioningService.changePassword(UserId.of(userId), request.password());
    }

    @PutMapping("/{userId}/status")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @RequiresPermission("user:manage")
    public void changeStatus(@PathVariable String userId,
                             @Valid @RequestBody ChangeStatusRequest request,
                             @CurrentUser AuthenticatedUser operator) {
        audit(operator, "變更狀態為 " + request.status(), userId);
        userProvisioningService.changeStatus(UserId.of(userId), request.status());
    }

    @PutMapping("/{userId}/roles")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @RequiresPermission("user:manage")
    public void replaceRoles(@PathVariable String userId,
                             @Valid @RequestBody ReplaceRolesRequest request,
                             @CurrentUser AuthenticatedUser operator) {
        audit(operator, "變更角色為 " + request.roleCodes(), userId);
        userProvisioningService.replaceRoles(UserId.of(userId), request.roleCodes());
    }

    private static void audit(AuthenticatedUser operator, String action, String target) {
        log.info("管理操作: operator={}, action={}, target={}", operator.userId(), action, target);
    }
}
