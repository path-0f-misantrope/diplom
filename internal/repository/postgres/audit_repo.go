package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/securestorage/internal/domain"
)

// AuditRepository defines the interface for AuditLog data access.
type AuditRepository interface {
	Create(ctx context.Context, log *domain.AuditLog) error
	List(ctx context.Context, limit, offset int) ([]*domain.AuditLog, int64, error)
}

type auditRepo struct {
	pool *pgxpool.Pool
}

// NewAuditRepository returns a new instance of AuditRepository.
func NewAuditRepository(pool *pgxpool.Pool) AuditRepository {
	return &auditRepo{pool: pool}
}

func (r *auditRepo) Create(ctx context.Context, log *domain.AuditLog) error {
	query := `
		INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address, user_agent, status, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`
	_, err := r.pool.Exec(ctx, query,
		log.UserID,
		log.Action,
		log.Resource,
		log.ResourceID,
		log.IPAddress,
		log.UserAgent,
		log.Status,
		log.Details,
	)
	if err != nil {
		return fmt.Errorf("auditRepo.Create: %w", err)
	}
	return nil
}

func (r *auditRepo) List(ctx context.Context, limit, offset int) ([]*domain.AuditLog, int64, error) {
	countQuery := `SELECT COUNT(*) FROM audit_logs`
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("auditRepo.List count: %w", err)
	}

	query := `
		SELECT id, user_id, action, resource, resource_id, ip_address, user_agent, status, details, created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("auditRepo.List: %w", err)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		var l domain.AuditLog
		if err := rows.Scan(
			&l.ID,
			&l.UserID,
			&l.Action,
			&l.Resource,
			&l.ResourceID,
			&l.IPAddress,
			&l.UserAgent,
			&l.Status,
			&l.Details,
			&l.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("auditRepo.List scan: %w", err)
		}
		logs = append(logs, &l)
	}

	return logs, total, rows.Err()
}
