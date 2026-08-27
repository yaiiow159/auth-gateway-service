package com.example.auth.gateway.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.contract.AuthenticatedUser;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AccessPolicyChainTest {

    private static final AccessContext CONTEXT = new AccessContext(
            "/api/orders/1", "GET", new AuthenticatedUser("1024", "timmy", Set.of(), Set.of(), null));

    @Test
    @DisplayName("第一個表態的策略決定結果，後續策略不再評估")
    void firstNonAbstainingPolicyWins() {
        List<String> evaluated = new ArrayList<>();

        AccessPolicyChain chain = new AccessPolicyChain(List.of(
                recording(evaluated, "second", AccessDecision.DENY, 10),
                recording(evaluated, "first", AccessDecision.PERMIT, 1)),
                AccessDecision.DENY);

        assertThat(chain.evaluate(CONTEXT)).isEqualTo(AccessDecision.PERMIT);
        assertThat(evaluated).containsExactly("first");
    }

    @Test
    @DisplayName("依 order 由小到大評估，與註冊順序無關")
    void evaluatesPoliciesInOrder() {
        List<String> evaluated = new ArrayList<>();

        AccessPolicyChain chain = new AccessPolicyChain(List.of(
                recording(evaluated, "late", AccessDecision.ABSTAIN, 100),
                recording(evaluated, "early", AccessDecision.ABSTAIN, -100),
                recording(evaluated, "middle", AccessDecision.ABSTAIN, 0)),
                AccessDecision.PERMIT);

        chain.evaluate(CONTEXT);

        assertThat(evaluated).containsExactly("early", "middle", "late");
    }

    @Test
    @DisplayName("全部棄權時採用兜底判定")
    void fallsBackWhenAllPoliciesAbstain() {
        AccessPolicyChain denyByDefault = new AccessPolicyChain(
                List.of(recording(new ArrayList<>(), "abstain", AccessDecision.ABSTAIN, 0)), AccessDecision.DENY);

        assertThat(denyByDefault.evaluate(CONTEXT)).isEqualTo(AccessDecision.DENY);
    }

    @Test
    @DisplayName("兜底值不可能是棄權，設成 ABSTAIN 會被修正為 DENY")
    void neverFallsBackToAbstain() {
        AccessPolicyChain chain = new AccessPolicyChain(List.of(), AccessDecision.ABSTAIN);

        assertThat(chain.evaluate(CONTEXT)).isEqualTo(AccessDecision.DENY);
    }

    private static AccessPolicy recording(List<String> log, String name, AccessDecision decision, int order) {
        return new AccessPolicy() {
            @Override
            public AccessDecision evaluate(AccessContext context) {
                log.add(name);
                return decision;
            }

            @Override
            public int order() {
                return order;
            }

            @Override
            public String name() {
                return name;
            }
        };
    }
}
