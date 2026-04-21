// Package postgres — репозиторий зашифрованных секретов.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/securestorage/internal/domain"
)

// ErrSecretNotFound — секрет не найден в БД.
var ErrSecretNotFound = errors.New("secret: не найден")

// ErrSecretForbidden — текущий пользователь не является владельцем секрета.
var ErrSecretForbidden = errors.New("secret: доступ запрещён")

// SecretRepository — интерфейс репозитория секретов.
type SecretRepository interface {
	Create(ctx context.Context, s *domain.Secret) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Secret, error)
	ListByOwner(ctx context.Context, ownerID uuid.UUID, limit, offset int) ([]*domain.Secret, int64, error)
	ListAll(ctx context.Context, limit, offset int) ([]*domain.Secret, int64, error)
	Update(ctx context.Context, s *domain.Secret) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// secretRepo — конкретная реализация SecretRepository.
type secretRepo struct {
	pool *pgxpool.Pool
}

// NewSecretRepository создаёт новый secretRepo.
func NewSecretRepository(pool *pgxpool.Pool) SecretRepository {
	return &secretRepo{pool: pool}
}

// Create вставляет новый секрет в БД.
func (r *secretRepo) Create(ctx context.Context, s *domain.Secret) error {
	query := `
		INSERT INTO secrets (id, owner_id, title, encrypted_data, iv, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
	`
	_, err := r.pool.Exec(ctx, query,
		s.ID, s.OwnerID, s.Title, s.EncryptedData, s.IV,
	)
	if err != nil {
		return fmt.Errorf("secretRepo.Create: %w", err)
	}
	return nil
}

// GetByID возвращает секрет по ID.
func (r *secretRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.Secret, error) {
	query := `
		SELECT id, owner_id, title, encrypted_data, iv, created_at, updated_at
		FROM secrets
		WHERE id = $1
	`
	s := &domain.Secret{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.OwnerID, &s.Title, &s.EncryptedData, &s.IV,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("secretRepo.GetByID: %w", err)
	}
	return s, nil
}

// ListByOwner возвращает секреты конкретного владельца (с пагинацией).
func (r *secretRepo) ListByOwner(
	ctx context.Context,
	ownerID uuid.UUID,
	limit, offset int,
) ([]*domain.Secret, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM secrets WHERE owner_id = $1`, ownerID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("secretRepo.ListByOwner count: %w", err)
	}

	query := `
		SELECT id, owner_id, title, encrypted_data, iv, created_at, updated_at
		FROM secrets
		WHERE owner_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	return r.querySecrets(ctx, query, ownerID, limit, offset)
}

// ListAll возвращает все секреты (для admin/manager).
func (r *secretRepo) ListAll(ctx context.Context, limit, offset int) ([]*domain.Secret, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM secrets`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("secretRepo.ListAll count: %w", err)
	}

	query := `
		SELECT id, owner_id, title, encrypted_data, iv, created_at, updated_at
		FROM secrets
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	secrets, _, err := r.querySecrets(ctx, query, limit, offset)
	return secrets, total, err
}

// Update обновляет заголовок и зашифрованные данные секрета.
func (r *secretRepo) Update(ctx context.Context, s *domain.Secret) error {
	query := `
		UPDATE secrets
		SET title = $1, encrypted_data = $2, iv = $3, updated_at = NOW()
		WHERE id = $4
	`
	tag, err := r.pool.Exec(ctx, query, s.Title, s.EncryptedData, s.IV, s.ID)
	if err != nil {
		return fmt.Errorf("secretRepo.Update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSecretNotFound
	}
	return nil
}

// Delete удаляет секрет по ID.
func (r *secretRepo) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM secrets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("secretRepo.Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSecretNotFound
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (r *secretRepo) querySecrets(ctx context.Context, query string, args ...any) ([]*domain.Secret, int64, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("secretRepo.querySecrets: %w", err)
	}
	defer rows.Close()

	var secrets []*domain.Secret
	for rows.Next() {
		s := &domain.Secret{}
		if err := rows.Scan(
			&s.ID, &s.OwnerID, &s.Title, &s.EncryptedData, &s.IV,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("secretRepo.querySecrets scan: %w", err)
		}
		secrets = append(secrets, s)
	}

	return secrets, int64(len(secrets)), rows.Err()
}
