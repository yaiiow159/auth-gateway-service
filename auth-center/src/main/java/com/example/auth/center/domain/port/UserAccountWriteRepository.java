package com.example.auth.center.domain.port;

import com.example.auth.center.domain.model.AccountStatus;
import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import java.util.Set;

/**
 * 使用者帳號的寫入出口。
 *
 * <p>與 {@link UserAccountRepository} 分開的理由是介面隔離：讀取端（認證、換發）
 * 是每個請求都會經過的高頻路徑，寫入端只有管理後台會用到。兩者的呼叫者、
 * 效能要求與變更頻率都不同，綁在同一個介面上只會讓讀取端被迫認識一堆用不到的方法。
 */
public interface UserAccountWriteRepository {

    boolean existsByUsername(String username);

    /**
     * 建立帳號。
     *
     * @param roleCodes 角色代碼；其中任何一個不存在時應拋出例外，而不是靜默略過 ——
     *                  靜默略過會產生一個「看起來建好了、實際上沒有權限」的帳號
     */
    UserAccount create(UserId id, String username, String passwordHash, String tenantId, Set<String> roleCodes);

    void updatePasswordHash(UserId userId, String passwordHash);

    void updateStatus(UserId userId, AccountStatus status);

    void replaceRoles(UserId userId, Set<String> roleCodes);
}
