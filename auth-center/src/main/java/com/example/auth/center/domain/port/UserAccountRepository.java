package com.example.auth.center.domain.port;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import java.util.Optional;

/**
 * 使用者帳號的查詢出口（Port）。
 *
 * <p>領域層只描述「需要什麼」，至於資料來自 JPA、LDAP 還是外部 IdP，由 Adapter 決定。
 */
public interface UserAccountRepository {

    Optional<UserAccount> findByUsername(String username);

    Optional<UserAccount> findById(UserId userId);
}
