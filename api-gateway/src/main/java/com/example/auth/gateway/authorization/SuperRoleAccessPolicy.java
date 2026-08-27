package com.example.auth.gateway.authorization;

/**
 * 超級角色直通策略。
 *
 * <p>排在鏈的最前端，讓平台管理角色不受路徑規則限制。
 * 它只會回傳 {@link AccessDecision#PERMIT} 或 {@link AccessDecision#ABSTAIN} ——
 * 「不是超級角色」不等於「應該被拒絕」，那是後續策略的職責。
 */
public class SuperRoleAccessPolicy implements AccessPolicy {

    private static final int ORDER = -100;

    private final String superRole;

    public SuperRoleAccessPolicy(String superRole) {
        this.superRole = superRole;
    }

    @Override
    public AccessDecision evaluate(AccessContext context) {
        return context.user().hasRole(superRole) ? AccessDecision.PERMIT : AccessDecision.ABSTAIN;
    }

    @Override
    public int order() {
        return ORDER;
    }
}
