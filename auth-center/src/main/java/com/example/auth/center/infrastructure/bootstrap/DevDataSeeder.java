package com.example.auth.center.infrastructure.bootstrap;

import com.example.auth.center.domain.model.AccountStatus;
import com.example.auth.center.domain.port.PasswordHasher;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * 開發用的示範帳號。
 *
 * <p>密碼在執行期才以 {@link PasswordHasher} 雜湊，因此版本庫裡不會出現任何雜湊值 ——
 * 一旦把 BCrypt 雜湊寫進 {@code data.sql}，它就會永久留在 git 歷史裡。
 *
 * <p>只在 {@code dev} profile 生效，正式環境的帳號應由使用者管理後台建立。
 */
@Configuration(proxyBeanMethods = false)
@Profile("dev")
public class DevDataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);
    private static final String DEMO_PASSWORD = "Passw0rd!";

    private record DemoUser(String id, String username, String tenantId, String roleId) {
    }

    private static final List<DemoUser> DEMO_USERS = List.of(
            new DemoUser("1024", "admin", "tenant-a", "r-admin"),
            new DemoUser("2048", "alice", "tenant-a", "r-user"));

    @Bean
    public ApplicationRunner seedDemoUsers(JdbcTemplate jdbcTemplate, PasswordHasher passwordHasher) {
        return args -> {
            Integer existing = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM auth_user", Integer.class);
            if (existing != null && existing > 0) {
                return;
            }
            String passwordHash = passwordHasher.hash(DEMO_PASSWORD);
            DEMO_USERS.forEach(user -> insert(jdbcTemplate, user, passwordHash));
            log.warn("已建立開發用示範帳號 {} ，密碼為 {}（僅限 dev profile）",
                    DEMO_USERS.stream().map(DemoUser::username).toList(), DEMO_PASSWORD);
        };
    }

    private void insert(JdbcTemplate jdbcTemplate, DemoUser user, String passwordHash) {
        jdbcTemplate.update(
                "INSERT INTO auth_user (id, username, password_hash, tenant_id, status) VALUES (?, ?, ?, ?, ?)",
                user.id(), user.username(), passwordHash, user.tenantId(), AccountStatus.ACTIVE.name());
        jdbcTemplate.update(
                "INSERT INTO auth_user_role (user_id, role_id) VALUES (?, ?)",
                user.id(), user.roleId());
    }
}
