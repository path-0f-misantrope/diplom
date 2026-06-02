package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/yourusername/securestorage/internal/domain"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
)

// AuditService defines operations for audit logging.
type AuditService interface {
	LogAction(ctx context.Context, userID *uuid.UUID, action string, resource *string, resourceID *uuid.UUID, ipAddress *string, userAgent *string, status string, details *string)
	ListLogs(ctx context.Context, limit, offset int) ([]*domain.AuditLog, int64, error)
}

type auditService struct {
	repo pgRepo.AuditRepository
}

// NewAuditService creates a new AuditService.
func NewAuditService(repo pgRepo.AuditRepository) AuditService {
	return &auditService{repo: repo}
}

// LogAction asynchronously logs an action to the database so it doesn't block the request.
func (s *auditService) LogAction(ctx context.Context, userID *uuid.UUID, action string, resource *string, resourceID *uuid.UUID, ipAddress *string, userAgent *string, status string, details *string) {
	logEntry := &domain.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Status:     status,
		Details:    details,
	}
	
	// Create a new context so the database insert isn't cancelled if the request context ends
	bgCtx := context.Background()
	
	go func() {
		// We fire and forget. In a real production system we might want to log this error to an error tracking service.
		_ = s.repo.Create(bgCtx, logEntry)
	}()
}

// ListLogs retrieves a paginated list of audit logs.
func (s *auditService) ListLogs(ctx context.Context, limit, offset int) ([]*domain.AuditLog, int64, error) {
	return s.repo.List(ctx, limit, offset)
}
