-- ============================================================
--  001_init.up.sql
--  Начальная схема БД: роли, разрешения, пользователи,
--  секреты, медиа-объекты и аудит-лог.
-- ============================================================

-- Включаем расширения
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive text

-- ── Роли ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Предустановленные роли
INSERT INTO roles (name, description) VALUES
    ('admin',   'Полный доступ ко всем ресурсам системы'),
    ('manager', 'Управление пользователями, чтение всех ресурсов'),
    ('user',    'CRUD только своих ресурсов')
ON CONFLICT (name) DO NOTHING;

-- ── Разрешения ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS permissions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    VARCHAR(64) NOT NULL,   -- secrets, media, users
    action      VARCHAR(64) NOT NULL,   -- create, read, update, delete, upload, download
    description TEXT,
    UNIQUE (resource, action)
);

INSERT INTO permissions (resource, action, description) VALUES
    ('secrets', 'create',   'Создание секрета'),
    ('secrets', 'read',     'Чтение секрета'),
    ('secrets', 'read_any', 'Чтение любого секрета (admin/manager)'),
    ('secrets', 'update',   'Обновление секрета'),
    ('secrets', 'delete',   'Удаление секрета'),
    ('media',   'upload',   'Загрузка медиа-файла'),
    ('media',   'download', 'Скачивание медиа-файла'),
    ('media',   'download_any', 'Скачивание любого медиа-файла'),
    ('media',   'delete',   'Удаление медиа-файла'),
    ('users',   'create',   'Создание пользователя'),
    ('users',   'read',     'Чтение профиля пользователя'),
    ('users',   'update',   'Обновление пользователя'),
    ('users',   'delete',   'Удаление пользователя')
ON CONFLICT (resource, action) DO NOTHING;

-- ── Связь ролей и разрешений ──────────────────────────────────
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Назначаем разрешения ролям
DO $$
DECLARE
    admin_id   UUID;
    manager_id UUID;
    user_id    UUID;
BEGIN
    SELECT id INTO admin_id   FROM roles WHERE name = 'admin';
    SELECT id INTO manager_id FROM roles WHERE name = 'manager';
    SELECT id INTO user_id    FROM roles WHERE name = 'user';

    -- admin: все разрешения
    INSERT INTO role_permissions (role_id, permission_id)
        SELECT admin_id, id FROM permissions
        ON CONFLICT DO NOTHING;

    -- manager: чтение всего + управление пользователями (без delete)
    INSERT INTO role_permissions (role_id, permission_id)
        SELECT manager_id, id FROM permissions
        WHERE (resource = 'secrets' AND action IN ('read', 'read_any'))
           OR (resource = 'media'   AND action IN ('download', 'download_any'))
           OR (resource = 'users'   AND action IN ('create', 'read', 'update'))
        ON CONFLICT DO NOTHING;

    -- user: только свои ресурсы
    INSERT INTO role_permissions (role_id, permission_id)
        SELECT user_id, id FROM permissions
        WHERE (resource = 'secrets' AND action IN ('create', 'read', 'update', 'delete'))
           OR (resource = 'media'   AND action IN ('upload', 'download', 'delete'))
           OR (resource = 'users'   AND action = 'read')
        ON CONFLICT DO NOTHING;
END;
$$;

-- ── Пользователи ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      CITEXT      NOT NULL UNIQUE,
    email         CITEXT      NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role_id       UUID        NOT NULL REFERENCES roles(id),
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Функция обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── Секреты (зашифрованные текстовые данные) ──────────────────
CREATE TABLE IF NOT EXISTS secrets (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title          VARCHAR(255) NOT NULL,
    -- AES-256-GCM: encrypted_data = base64(ciphertext+tag), iv = base64(nonce)
    encrypted_data TEXT        NOT NULL,
    iv             VARCHAR(32) NOT NULL,   -- base64 encoded 12-byte nonce
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secrets_owner ON secrets(owner_id);

CREATE TRIGGER trg_secrets_updated_at
    BEFORE UPDATE ON secrets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── Медиа-объекты ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS media_objects (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename     VARCHAR(512) NOT NULL,               -- оригинальное имя файла
    content_type VARCHAR(128) NOT NULL,
    size_bytes   BIGINT       NOT NULL,               -- размер оригинала
    bucket_name  VARCHAR(256) NOT NULL,               -- MinIO bucket
    object_key   VARCHAR(512) NOT NULL,               -- MinIO object key (UUID)
    iv           VARCHAR(32)  NOT NULL,               -- base64 encoded nonce
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_media_owner ON media_objects(owner_id);

-- ── Аудит-лог ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(128) NOT NULL,
    resource    VARCHAR(64),
    resource_id UUID,
    ip_address  VARCHAR(64),
    user_agent  TEXT,
    status      VARCHAR(32) NOT NULL DEFAULT 'success',  -- success | failure
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user      ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created   ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource  ON audit_logs(resource, resource_id);
