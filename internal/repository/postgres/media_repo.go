// Package postgres — репозиторий медиа-объектов.
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

// ErrMediaNotFound — медиа-объект не найден.
var ErrMediaNotFound = errors.New("media: объект не найден")

// MediaRepository — интерфейс репозитория медиа-объектов.
type MediaRepository interface {
	Create(ctx context.Context, m *domain.MediaObject) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.MediaObject, error)
	ListByOwner(ctx context.Context, ownerID uuid.UUID, limit, offset int) ([]*domain.MediaObject, int64, error)
	ListAll(ctx context.Context, limit, offset int) ([]*domain.MediaObject, int64, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// mediaRepo — конкретная реализация MediaRepository.
type mediaRepo struct {
	pool *pgxpool.Pool
}

// NewMediaRepository создаёт новый mediaRepo.
func NewMediaRepository(pool *pgxpool.Pool) MediaRepository {
	return &mediaRepo{pool: pool}
}

// Create вставляет запись о медиа-объекте в БД.
func (r *mediaRepo) Create(ctx context.Context, m *domain.MediaObject) error {
	query := `
		INSERT INTO media_objects
		    (id, owner_id, filename, content_type, size_bytes, bucket_name, object_key, iv, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`
	_, err := r.pool.Exec(ctx, query,
		m.ID, m.OwnerID, m.Filename, m.ContentType,
		m.SizeBytes, m.BucketName, m.ObjectKey, m.IV,
	)
	if err != nil {
		return fmt.Errorf("mediaRepo.Create: %w", err)
	}
	return nil
}

// GetByID возвращает медиа-объект по ID.
func (r *mediaRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.MediaObject, error) {
	query := `
		SELECT id, owner_id, filename, content_type, size_bytes, bucket_name, object_key, iv, created_at
		FROM media_objects
		WHERE id = $1
	`
	m := &domain.MediaObject{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&m.ID, &m.OwnerID, &m.Filename, &m.ContentType,
		&m.SizeBytes, &m.BucketName, &m.ObjectKey, &m.IV, &m.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMediaNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mediaRepo.GetByID: %w", err)
	}
	return m, nil
}

// ListByOwner возвращает медиа-объекты конкретного владельца.
func (r *mediaRepo) ListByOwner(
	ctx context.Context,
	ownerID uuid.UUID,
	limit, offset int,
) ([]*domain.MediaObject, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM media_objects WHERE owner_id = $1`, ownerID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("mediaRepo.ListByOwner count: %w", err)
	}

	query := `
		SELECT id, owner_id, filename, content_type, size_bytes, bucket_name, object_key, iv, created_at
		FROM media_objects
		WHERE owner_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	items, err := r.queryMedia(ctx, query, ownerID, limit, offset)
	return items, total, err
}

// ListAll возвращает все медиа-объекты (для admin/manager).
func (r *mediaRepo) ListAll(ctx context.Context, limit, offset int) ([]*domain.MediaObject, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM media_objects`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("mediaRepo.ListAll count: %w", err)
	}

	query := `
		SELECT id, owner_id, filename, content_type, size_bytes, bucket_name, object_key, iv, created_at
		FROM media_objects
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	items, err := r.queryMedia(ctx, query, limit, offset)
	return items, total, err
}

// Delete удаляет запись о медиа-объекте из БД.
func (r *mediaRepo) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM media_objects WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("mediaRepo.Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMediaNotFound
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (r *mediaRepo) queryMedia(ctx context.Context, query string, args ...any) ([]*domain.MediaObject, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mediaRepo.queryMedia: %w", err)
	}
	defer rows.Close()

	var items []*domain.MediaObject
	for rows.Next() {
		m := &domain.MediaObject{}
		if err := rows.Scan(
			&m.ID, &m.OwnerID, &m.Filename, &m.ContentType,
			&m.SizeBytes, &m.BucketName, &m.ObjectKey, &m.IV, &m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("mediaRepo.queryMedia scan: %w", err)
		}
		items = append(items, m)
	}

	return items, rows.Err()
}
