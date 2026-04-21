// Package postgres реализует репозиторий пользователей на основе pgx.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"


	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/securestorage/internal/domain"
)

// ErrUserNotFound возвращается когда пользователь не найден в БД.
var ErrUserNotFound = errors.New("user: пользователь не найден")

// ErrEmailExists возвращается при попытке зарегистрировать занятый email.
var ErrEmailExists = errors.New("user: email уже зарегистрирован")

// ErrUsernameExists возвращается при попытке зарегистрировать занятый username.
var ErrUsernameExists = errors.New("user: username уже занят")

// UserRepository — интерфейс репозитория пользователей.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	List(ctx context.Context, limit, offset int) ([]*domain.User, int64, error)
	UpdateRole(ctx context.Context, userID, roleID uuid.UUID) error
	GetRoleByName(ctx context.Context, name string) (*domain.Role, error)
	GetRoleWithPermissions(ctx context.Context, roleID uuid.UUID) (*domain.Role, error)
}

// userRepo — конкретная реализация UserRepository.
type userRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepository создаёт новый экземпляр userRepo.
func NewUserRepository(pool *pgxpool.Pool) UserRepository {
	return &userRepo{pool: pool}
}

// Create вставляет нового пользователя в БД.
func (r *userRepo) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, role_id, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
	`
	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.RoleID,
		user.IsActive,
	)
	if err != nil {
		// Проверяем нарушение уникальности
		if isUniqueViolation(err, "users_email_key") {
			return ErrEmailExists
		}
		if isUniqueViolation(err, "users_username_key") {
			return ErrUsernameExists
		}
		return fmt.Errorf("userRepo.Create: %w", err)
	}
	return nil
}

// GetByID возвращает пользователя по его ID.
func (r *userRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, username, email, password_hash, role_id, is_active, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	return r.scanUser(ctx, query, id)
}

// GetByEmail возвращает пользователя по email.
func (r *userRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, username, email, password_hash, role_id, is_active, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	return r.scanUser(ctx, query, email)
}

// GetByUsername возвращает пользователя по username.
func (r *userRepo) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT id, username, email, password_hash, role_id, is_active, created_at, updated_at
		FROM users
		WHERE username = $1
	`
	return r.scanUser(ctx, query, username)
}

// List возвращает страницу пользователей с общим количеством.
func (r *userRepo) List(ctx context.Context, limit, offset int) ([]*domain.User, int64, error) {
	countQuery := `SELECT COUNT(*) FROM users`
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("userRepo.List count: %w", err)
	}

	query := `
		SELECT id, username, email, password_hash, role_id, is_active, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("userRepo.List: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u := &domain.User{}
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Email, &u.PasswordHash,
			&u.RoleID, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("userRepo.List scan: %w", err)
		}
		users = append(users, u)
	}

	return users, total, rows.Err()
}

// UpdateRole обновляет роль пользователя.
func (r *userRepo) UpdateRole(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `UPDATE users SET role_id = $1, updated_at = NOW() WHERE id = $2`
	tag, err := r.pool.Exec(ctx, query, roleID, userID)
	if err != nil {
		return fmt.Errorf("userRepo.UpdateRole: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// GetRoleByName возвращает роль по имени.
func (r *userRepo) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	query := `SELECT id, name, description, created_at FROM roles WHERE name = $1`
	role := &domain.Role{}
	err := r.pool.QueryRow(ctx, query, name).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("userRepo: роль %q не найдена", name)
	}
	if err != nil {
		return nil, fmt.Errorf("userRepo.GetRoleByName: %w", err)
	}
	return role, nil
}

// GetRoleWithPermissions возвращает роль вместе с её разрешениями.
func (r *userRepo) GetRoleWithPermissions(ctx context.Context, roleID uuid.UUID) (*domain.Role, error) {
	// Получаем роль
	roleQuery := `SELECT id, name, description, created_at FROM roles WHERE id = $1`
	role := &domain.Role{}
	err := r.pool.QueryRow(ctx, roleQuery, roleID).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("userRepo: роль с id=%s не найдена", roleID)
	}
	if err != nil {
		return nil, fmt.Errorf("userRepo.GetRoleWithPermissions role: %w", err)
	}

	// Получаем разрешения роли
	permQuery := `
		SELECT p.id, p.resource, p.action, p.description
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1
	`
	rows, err := r.pool.Query(ctx, permQuery, roleID)
	if err != nil {
		return nil, fmt.Errorf("userRepo.GetRoleWithPermissions perms: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		p := domain.Permission{}
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description); err != nil {
			return nil, fmt.Errorf("userRepo.GetRoleWithPermissions scan perm: %w", err)
		}
		role.Permissions = append(role.Permissions, p)
	}

	return role, rows.Err()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// scanUser выполняет запрос и сканирует одного пользователя.
func (r *userRepo) scanUser(ctx context.Context, query string, args ...any) (*domain.User, error) {
	u := &domain.User{}
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash,
		&u.RoleID, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("userRepo.scanUser: %w", err)
	}
	return u, nil
}

// isUniqueViolation проверяет нарушение UNIQUE constraint PostgreSQL (код 23505).
func isUniqueViolation(err error, constraint string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") && strings.Contains(msg, constraint)
}
