-- ============================================================
--  001_init.down.sql
--  Откат начальной схемы
-- ============================================================

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS media_objects;
DROP TABLE IF EXISTS secrets;
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP FUNCTION IF EXISTS update_updated_at();
DROP EXTENSION IF EXISTS "citext";
DROP EXTENSION IF EXISTS "pgcrypto";
