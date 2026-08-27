-- RBAC 的基礎結構：使用者、角色、權限，以及兩組多對多關聯。
--
-- 刻意只使用各家資料庫都支援的語法（VARCHAR、PRIMARY KEY、FOREIGN KEY），
-- 不使用 H2 的 MERGE 或 IF NOT EXISTS，讓同一份腳本能同時套用在
-- 開發用的 H2 與正式環境的 PostgreSQL 上。腳本一旦發布就不可再修改，
-- 任何結構調整都必須以新的版本號另開一份。

CREATE TABLE auth_user (
    id            VARCHAR(64)  NOT NULL,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    tenant_id     VARCHAR(64),
    status        VARCHAR(16)  NOT NULL,
    CONSTRAINT pk_auth_user PRIMARY KEY (id),
    CONSTRAINT uk_auth_user_username UNIQUE (username)
);

CREATE TABLE auth_role (
    id   VARCHAR(64) NOT NULL,
    code VARCHAR(64) NOT NULL,
    CONSTRAINT pk_auth_role PRIMARY KEY (id),
    CONSTRAINT uk_auth_role_code UNIQUE (code)
);

CREATE TABLE auth_permission (
    id   VARCHAR(64)  NOT NULL,
    code VARCHAR(128) NOT NULL,
    CONSTRAINT pk_auth_permission PRIMARY KEY (id),
    CONSTRAINT uk_auth_permission_code UNIQUE (code)
);

CREATE TABLE auth_user_role (
    user_id VARCHAR(64) NOT NULL,
    role_id VARCHAR(64) NOT NULL,
    CONSTRAINT pk_auth_user_role PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES auth_user (id),
    CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES auth_role (id)
);

CREATE TABLE auth_role_permission (
    role_id       VARCHAR(64) NOT NULL,
    permission_id VARCHAR(64) NOT NULL,
    CONSTRAINT pk_auth_role_permission PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_perm_role FOREIGN KEY (role_id) REFERENCES auth_role (id),
    CONSTRAINT fk_role_perm_perm FOREIGN KEY (permission_id) REFERENCES auth_permission (id)
);

-- 登入是最頻繁的查詢，username 的唯一約束已隱含索引；
-- 租戶維度的查詢則需要另外建立
CREATE INDEX idx_auth_user_tenant ON auth_user (tenant_id);
