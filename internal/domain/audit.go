package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog represents a record in the audit_logs table.
type AuditLog struct {
	ID         int64      `json:"id"`
	UserID     *uuid.UUID `json:"user_id"`
	Action     string     `json:"action"`
	Resource   *string    `json:"resource"`
	ResourceID *uuid.UUID `json:"resource_id"`
	IPAddress  *string    `json:"ip_address"`
	UserAgent  *string    `json:"user_agent"`
	Status     string     `json:"status"` // success or failure
	Details    *string    `json:"details"` // JSON string or simply text
	CreatedAt  time.Time  `json:"created_at"`
}

// AuditLogResponse is returned via API
type AuditLogResponse struct {
	ID         int64      `json:"id"`
	UserID     *uuid.UUID `json:"user_id"`
	Action     string     `json:"action"`
	Resource   *string    `json:"resource"`
	ResourceID *uuid.UUID `json:"resource_id"`
	IPAddress  *string    `json:"ip_address"`
	UserAgent  *string    `json:"user_agent"`
	Status     string     `json:"status"`
	Details    *string    `json:"details"`
	CreatedAt  time.Time  `json:"created_at"`
}
