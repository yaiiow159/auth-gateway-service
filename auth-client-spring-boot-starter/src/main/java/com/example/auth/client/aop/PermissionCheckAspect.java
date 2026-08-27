package com.example.auth.client.aop;

import com.example.auth.client.annotation.RequiresPermission;
import com.example.auth.client.context.ForbiddenException;
import com.example.auth.client.context.UserContextHolder;
import com.example.auth.contract.AuthenticatedUser;
import java.util.Set;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;

/**
 * 實作 {@link RequiresPermission} 的切面。
 *
 * <p>用 AOP 而非在每個方法開頭寫 {@code if (!user.hasPermission(...)) throw ...}，
 * 是因為權限檢查是典型的橫切關注點：它會出現在幾百個方法裡、邏輯完全一致，
 * 而且一旦有人漏寫就是一個安全漏洞。集中成切面之後，「有沒有保護」變成看註解就知道的事。
 */
@Aspect
public class PermissionCheckAspect {

    @Pointcut("@annotation(requiresPermission)")
    public void annotatedMethod(RequiresPermission requiresPermission) {
        // 切點宣告，方法本身不需要實作
    }

    @Before(value = "annotatedMethod(requiresPermission)", argNames = "requiresPermission")
    public void checkPermission(RequiresPermission requiresPermission) {
        AuthenticatedUser user = UserContextHolder.require();
        Set<String> required = Set.of(requiresPermission.value());

        boolean permitted = requiresPermission.requireAll()
                ? user.hasAllPermissions(required)
                : user.hasAnyPermission(required);

        if (!permitted) {
            throw new ForbiddenException(required);
        }
    }
}
