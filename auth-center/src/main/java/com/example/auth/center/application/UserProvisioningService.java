package com.example.auth.center.application;

import com.example.auth.center.domain.model.AccountStatus;
import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.model.UserId;
import com.example.auth.center.domain.port.PasswordHasher;
import com.example.auth.center.domain.port.RefreshTokenStore;
import com.example.auth.center.domain.port.UserAccountWriteRepository;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 使用者與角色的管理用例。
 *
 * <p><b>每個寫入操作都必須考慮它對「已經發出去的憑證」有什麼影響。</b>
 * 這是這個服務最容易被寫錯的地方：只改資料庫是不夠的，因為使用者手上還握著
 * 依照舊狀態簽發的 Token。
 *
 * <ul>
 *   <li>改密碼、停權 —— 撤銷該使用者全部 Refresh Token，強制重新登入。
 *       這正是「改了密碼卻還能繼續用」這類事故的來源。</li>
 *   <li>改角色 —— 不撤銷。權限異動會在下一次換發時生效，最長延遲一個 Access Token 的壽命
 *       （預設 10 分鐘）。這是 ADR-0001 已經接受的取捨；若某次調整需要立即生效，
 *       應搭配一次明確的強制登出，而不是讓每次改角色都踢掉使用者。</li>
 * </ul>
 *
 * <p>Access Token 本身無法被個別撤銷（除非知道它的 jti），因此上述操作的實際生效時間
 * 仍受限於 Access Token 的剩餘壽命 —— 這是無狀態驗簽架構的固有代價，
 * 也是把 Access Token 設得夠短的理由。
 */
@Service
public class UserProvisioningService {

    private static final Logger log = LoggerFactory.getLogger(UserProvisioningService.class);

    private final UserAccountWriteRepository writeRepository;
    private final PasswordHasher passwordHasher;
    private final RefreshTokenStore refreshTokenStore;

    public UserProvisioningService(UserAccountWriteRepository writeRepository,
                                   PasswordHasher passwordHasher,
                                   RefreshTokenStore refreshTokenStore) {
        this.writeRepository = writeRepository;
        this.passwordHasher = passwordHasher;
        this.refreshTokenStore = refreshTokenStore;
    }

    public UserAccount createUser(CreateUserCommand command) {
        if (writeRepository.existsByUsername(command.username())) {
            throw new UsernameAlreadyTakenException(command.username());
        }
        UserAccount created = writeRepository.create(
                UserId.of(UUID.randomUUID().toString()),
                command.username(),
                passwordHasher.hash(command.rawPassword()),
                command.tenantId(),
                command.roleCodes());

        log.info("建立帳號: userId={}, username={}, roles={}",
                created.id(), created.username(), created.roles());
        return created;
    }

    public void changePassword(UserId userId, String rawPassword) {
        writeRepository.updatePasswordHash(userId, passwordHasher.hash(rawPassword));
        refreshTokenStore.revokeAll(userId);
        log.info("變更密碼並撤銷全部 Refresh Token: userId={}", userId);
    }

    public void changeStatus(UserId userId, AccountStatus status) {
        writeRepository.updateStatus(userId, status);
        if (status != AccountStatus.ACTIVE) {
            refreshTokenStore.revokeAll(userId);
        }
        log.info("變更帳號狀態: userId={}, status={}", userId, status);
    }

    public void replaceRoles(UserId userId, Set<String> roleCodes) {
        writeRepository.replaceRoles(userId, roleCodes);
        log.info("變更角色: userId={}, roles={}", userId, roleCodes);
    }
}
