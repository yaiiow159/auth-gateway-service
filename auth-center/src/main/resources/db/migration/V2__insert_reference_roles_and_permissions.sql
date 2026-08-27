-- 角色與權限屬於參考資料（reference data）：應用程式的授權邏輯直接依賴這些代碼，
-- 因此它們必須存在於每一個環境，而不是只在開發環境被種入。
--
-- 這裡不含任何使用者或密碼。示範帳號由 DevDataSeeder 在執行期產生，
-- 密碼雜湊因此不會進入版本庫與遷移歷史。

INSERT INTO auth_permission (id, code) VALUES ('p-order-read', 'order:read');
INSERT INTO auth_permission (id, code) VALUES ('p-order-create', 'order:create');
INSERT INTO auth_permission (id, code) VALUES ('p-order-delete', 'order:delete');
INSERT INTO auth_permission (id, code) VALUES ('p-user-manage', 'user:manage');

INSERT INTO auth_role (id, code) VALUES ('r-admin', 'ROLE_ADMIN');
INSERT INTO auth_role (id, code) VALUES ('r-user', 'ROLE_USER');

INSERT INTO auth_role_permission (role_id, permission_id) VALUES ('r-admin', 'p-order-read');
INSERT INTO auth_role_permission (role_id, permission_id) VALUES ('r-admin', 'p-order-create');
INSERT INTO auth_role_permission (role_id, permission_id) VALUES ('r-admin', 'p-order-delete');
INSERT INTO auth_role_permission (role_id, permission_id) VALUES ('r-admin', 'p-user-manage');

INSERT INTO auth_role_permission (role_id, permission_id) VALUES ('r-user', 'p-order-read');
INSERT INTO auth_role_permission (role_id, permission_id) VALUES ('r-user', 'p-order-create');
