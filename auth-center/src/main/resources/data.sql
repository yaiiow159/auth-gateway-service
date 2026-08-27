-- 角色與權限的基礎資料（不含密碼，因此可以安全地寫在腳本中）。
-- 使用者與密碼由 DevDataSeeder 在 dev profile 下產生，避免把雜湊值提交進版控。

MERGE INTO auth_permission (id, code) KEY (id) VALUES ('p-order-read', 'order:read');
MERGE INTO auth_permission (id, code) KEY (id) VALUES ('p-order-create', 'order:create');
MERGE INTO auth_permission (id, code) KEY (id) VALUES ('p-order-delete', 'order:delete');
MERGE INTO auth_permission (id, code) KEY (id) VALUES ('p-user-manage', 'user:manage');

MERGE INTO auth_role (id, code) KEY (id) VALUES ('r-admin', 'ROLE_ADMIN');
MERGE INTO auth_role (id, code) KEY (id) VALUES ('r-user', 'ROLE_USER');

MERGE INTO auth_role_permission (role_id, permission_id) KEY (role_id, permission_id) VALUES ('r-admin', 'p-order-read');
MERGE INTO auth_role_permission (role_id, permission_id) KEY (role_id, permission_id) VALUES ('r-admin', 'p-order-create');
MERGE INTO auth_role_permission (role_id, permission_id) KEY (role_id, permission_id) VALUES ('r-admin', 'p-order-delete');
MERGE INTO auth_role_permission (role_id, permission_id) KEY (role_id, permission_id) VALUES ('r-admin', 'p-user-manage');

MERGE INTO auth_role_permission (role_id, permission_id) KEY (role_id, permission_id) VALUES ('r-user', 'p-order-read');
MERGE INTO auth_role_permission (role_id, permission_id) KEY (role_id, permission_id) VALUES ('r-user', 'p-order-create');
