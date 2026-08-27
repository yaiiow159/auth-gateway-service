package com.example.auth.center.application;

import com.example.auth.center.domain.model.UserAccount;
import com.example.auth.center.domain.port.PasswordHasher;
import com.example.auth.center.domain.port.UserAccountRepository;
import com.example.auth.center.domain.token.TokenPair;
import com.example.auth.contract.AuthErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 登入用例。
 *
 * <p>刻意讓「帳號不存在」與「密碼錯誤」回傳完全相同的錯誤碼，避免攻擊者藉由
 * 錯誤訊息的差異列舉出系統中存在哪些帳號。
 */
@Service
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserAccountRepository userAccountRepository;
    private final PasswordHasher passwordHasher;
    private final TokenPairFactory tokenPairFactory;

    public AuthenticationService(UserAccountRepository userAccountRepository,
                                 PasswordHasher passwordHasher,
                                 TokenPairFactory tokenPairFactory) {
        this.userAccountRepository = userAccountRepository;
        this.passwordHasher = passwordHasher;
        this.tokenPairFactory = tokenPairFactory;
    }

    public TokenPair login(LoginCommand command) {
        UserAccount account = userAccountRepository.findByUsername(command.username())
                .orElseThrow(() -> credentialsInvalid(command.username()));

        if (!passwordHasher.matches(command.rawPassword(), account.passwordHash())) {
            throw credentialsInvalid(command.username());
        }
        if (!account.canLogin()) {
            log.info("帳號狀態不允許登入: username={}, status={}", account.username(), account.status());
            throw new AuthenticationFailedException(AuthErrorCode.ACCOUNT_DISABLED);
        }

        log.info("登入成功: userId={}, username={}", account.id(), account.username());
        return tokenPairFactory.createFor(account);
    }

    private AuthenticationFailedException credentialsInvalid(String username) {
        log.info("登入失敗: username={}", username);
        return new AuthenticationFailedException(AuthErrorCode.CREDENTIALS_INVALID);
    }
}
