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
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * 開發用的示範帳號。
 *
 * <p>密碼在執行期才以 {@link PasswordHasher} 雜湊，因此版本庫裡不會出現任何雜湊值 ——
 * 一旦把 BCrypt 雜湊寫進 {@code data.sql}，它就會永久留在 git 歷史裡。
 *
 * <p>兩道獨立的防線，缺一不可：
 * <ol>
 *   <li>{@code @Profile("dev")} —— 必須明確啟用 dev profile。</li>
 *   <li>連線必須指向記憶體內的 H2 —— 即使有人誤啟 dev profile 而資料來源卻是真實資料庫，
 *       也不會有任何一筆已知密碼的帳號被寫進去。</li>
 * </ol>
 * 只靠 profile 是不夠的：profile 是一個很容易在部署腳本裡設錯或忘記設的字串。
 */
@Configuration(proxyBeanMethods = false)
@Profile("dev")
public class DevDataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);
    private static final String DEMO_PASSWORD = "Passw0rd!";
    private static final String EMBEDDED_URL_PREFIX = "jdbc:h2:mem:";

    private record DemoUser(String id, String username, String tenantId, String roleId) {
    }

    private static final List<DemoUser> DEMO_USERS = List.of(
            new DemoUser("1024", "admin", "tenant-a", "r-admin"),
            new DemoUser("2048", "alice", "tenant-a", "r-user"));

    @Bean
    public ApplicationRunner seedDemoUsers(JdbcTemplate jdbcTemplate, PasswordHasher passwordHasher) {
        return args -> {
            if (!isEmbeddedDatabase(jdbcTemplate)) {
                log.warn("偵測到非記憶體內資料庫，略過示範帳號建立；"
                        + "若這是正式環境，請確認未誤啟 dev profile");
                return;
            }
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

    /** 以實際連線的 JDBC URL 判斷，而非設定值 —— 設定可以被覆寫，連線不會說謊。 */
    private boolean isEmbeddedDatabase(JdbcTemplate jdbcTemplate) {
        String url = jdbcTemplate.execute(
                (ConnectionCallback<String>) connection -> connection.getMetaData().getURL());
        return url != null && url.startsWith(EMBEDDED_URL_PREFIX);
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
