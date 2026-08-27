-- 授權中心的 RBAC 結構。
-- 正式專案應改由 Flyway / Liquibase 管理版本；此處為求最小可執行示範而直接使用初始化腳本。

CREATE TABLE IF NOT EXISTS auth_user (
    id            VARCHAR(64)  NOT NULL PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    tenant_id     VARCHAR(64),
    status        VARCHAR(16)  NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_role (
    id   VARCHAR(64) NOT NULL PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS auth_permission (
    id   VARCHAR(64)  NOT NULL PRIMARY KEY,
    code VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS auth_user_role (
    user_id VARCHAR(64) NOT NULL,
    role_id VARCHAR(64) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES auth_user (id),
    CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES auth_role (id)
);

CREATE TABLE IF NOT EXISTS auth_role_permission (
    role_id       VARCHAR(64) NOT NULL,
    permission_id VARCHAR(64) NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_perm_role FOREIGN KEY (role_id) REFERENCES auth_role (id),
    CONSTRAINT fk_role_perm_perm FOREIGN KEY (permission_id) REFERENCES auth_permission (id)
);

-- 登入路徑上最頻繁的查詢，UNIQUE 約束已隱含索引，此處僅標註意圖
CREATE INDEX IF NOT EXISTS idx_auth_user_tenant ON auth_user (tenant_id);
