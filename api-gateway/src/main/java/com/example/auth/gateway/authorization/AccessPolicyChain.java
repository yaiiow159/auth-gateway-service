package com.example.auth.gateway.authorization;

import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 責任鏈：依序詢問每個策略，第一個表態的說了算。
 *
 * <p>所有策略都棄權時採用 {@code fallbackDecision}。這個預設值是整套授權模型中
 * 最需要被慎重決定的一個開關，語意上等同於「網關對未被規則覆蓋的路徑抱持什麼態度」。
 */
public class AccessPolicyChain {

    private static final Logger log = LoggerFactory.getLogger(AccessPolicyChain.class);

    private final List<AccessPolicy> policies;
    private final AccessDecision fallbackDecision;

    public AccessPolicyChain(List<AccessPolicy> policies, AccessDecision fallbackDecision) {
        this.policies = policies.stream()
                .sorted(Comparator.comparingInt(AccessPolicy::order))
                .toList();
        this.fallbackDecision = fallbackDecision == AccessDecision.ABSTAIN
                ? AccessDecision.DENY // 兜底值不可能是棄權，否則等於沒有結論
                : fallbackDecision;
    }

    public AccessDecision evaluate(AccessContext context) {
        for (AccessPolicy policy : policies) {
            AccessDecision decision = policy.evaluate(context);
            if (decision != AccessDecision.ABSTAIN) {
                log.debug("授權判定 {} 由策略 {} 決定: {} {}",
                        decision, policy.name(), context.method(), context.path());
                return decision;
            }
        }
        return fallbackDecision;
    }
}
