package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/securestorage/internal/service"
)

// AuditHandler provides endpoints for audit logs.
type AuditHandler struct {
	auditSvc service.AuditService
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(auditSvc service.AuditService) *AuditHandler {
	return &AuditHandler{auditSvc: auditSvc}
}

// ListLogs godoc
// @Summary Список аудит-логов (только admin)
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param limit  query int false "Лимит записей"
// @Param offset query int false "Смещение"
// @Success 200 {object} PaginatedResponse
// @Router /api/v1/admin/audit-logs [get]
func (h *AuditHandler) ListLogs(c *gin.Context) {
	limit, offset := parsePagination(c)

	logs, total, err := h.auditSvc.ListLogs(c.Request.Context(), limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("AuditHandler.ListLogs")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ошибка получения логов"})
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse{
		Data:   logs,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}
