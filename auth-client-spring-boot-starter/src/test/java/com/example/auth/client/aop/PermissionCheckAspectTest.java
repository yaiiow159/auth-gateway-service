package com.example.auth.client.aop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.client.annotation.RequiresPermission;
import com.example.auth.client.context.ForbiddenException;
import com.example.auth.client.context.MissingIdentityException;
import com.example.auth.client.context.UserContextHolder;
import com.example.auth.contract.AuthenticatedUser;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;

/**
 * 這道切面是繞過網關直連服務時的最後一道防線，它的「拒絕」路徑必須被實際驗證過。
 *
 * <p>端到端測試涵蓋不到這裡：權限不足的請求在網關就被 403 擋下，根本到不了服務，
 * 因此切面實際上永遠只走過放行分支。
 *
 * <p>測試目標刻意使用不實作任何介面的類別，以強制產生 CGLIB 代理 ——
 * 註解標在實作方法上，這與 Controller 的實際情況一致。若改用介面加 JDK 動態代理，
 * 介面方法上的註解不會被實作方法繼承，切面根本不會生效。
 */
class PermissionCheckAspectTest {

    static class OrderApi {

        @RequiresPermission("order:create")
        String create() {
            return "created";
        }

        @RequiresPermission(value = {"order:read", "order:delete"}, requireAll = true)
        String delete() {
            return "deleted";
        }

        @RequiresPermission({"order:read", "order:export"})
        String read() {
            return "read";
        }

        String unprotected() {
            return "ok";
        }
    }

    private final OrderApi api = proxy();

    @AfterEach
    void clearContext() {
        UserContextHolder.clear();
    }

    @Test
    @DisplayName("具備所需權限時放行")
    void permitsWhenPermissionPresent() {
        authenticateWith("order:create");

        assertThat(api.create()).isEqualTo("created");
    }

    @Test
    @DisplayName("缺少所需權限時拒絕，並指出缺的是哪一項")
    void deniesWhenPermissionMissing() {
        authenticateWith("order:read");

        assertThatThrownBy(api::create)
                .isInstanceOf(ForbiddenException.class)
                .extracting(e -> ((ForbiddenException) e).requiredPermissions())
                .isEqualTo(Set.of("order:create"));
    }

    @Test
    @DisplayName("requireAll 為真時必須具備全部權限，只有其一仍被拒絕")
    void requiresEveryPermissionWhenRequireAll() {
        authenticateWith("order:read");
        assertThatThrownBy(api::delete).isInstanceOf(ForbiddenException.class);

        authenticateWith("order:read", "order:delete");
        assertThat(api.delete()).isEqualTo("deleted");
    }

    @Test
    @DisplayName("requireAll 為假時具備任一權限即可")
    void requiresAnyPermissionByDefault() {
        authenticateWith("order:export");

        assertThat(api.read()).isEqualTo("read");
    }

    @Test
    @DisplayName("匿名請求觸及受保護方法時視為缺少身分，而非權限不足")
    void rejectsAnonymousCaller() {
        UserContextHolder.clear();

        assertThatThrownBy(api::create).isInstanceOf(MissingIdentityException.class);
    }

    @Test
    @DisplayName("未標註的方法不受切面影響")
    void leavesUnannotatedMethodsAlone() {
        UserContextHolder.clear();

        assertThatCode(api::unprotected).doesNotThrowAnyException();
    }

    private static void authenticateWith(String... permissions) {
        UserContextHolder.set(new AuthenticatedUser(
                "2048", "timmy", Set.of("ROLE_USER"), Set.of(permissions), "tenant-a"));
    }

    private static OrderApi proxy() {
        AspectJProxyFactory factory = new AspectJProxyFactory(new OrderApi());
        factory.setProxyTargetClass(true);
        factory.addAspect(new PermissionCheckAspect());
        return factory.getProxy();
    }
}
