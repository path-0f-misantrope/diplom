// Package handler реализует HTTP-хендлеры управления зашифрованными секретами.
package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/securestorage/internal/domain"
	"github.com/yourusername/securestorage/internal/middleware"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
	"github.com/yourusername/securestorage/internal/service"
)

// SecretHandler — хендлер управления секретами.
type SecretHandler struct {
	secretSvc service.SecretService
}

// NewSecretHandler создаёт новый SecretHandler.
func NewSecretHandler(secretSvc service.SecretService) *SecretHandler {
	return &SecretHandler{secretSvc: secretSvc}
}

// Create godoc
// @Summary Создать новый секрет
// @Tags secrets
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body domain.CreateSecretRequest true "Данные секрета"
// @Success 201 {object} domain.SecretResponse
// @Failure 400,401,500 {object} ErrorResponse
// @Router /api/v1/secrets [post]
func (h *SecretHandler) Create(c *gin.Context) {
	claims := middleware.GetClaims(c)

	var req domain.CreateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	resp, err := h.secretSvc.Create(c.Request.Context(), claims.UserID, req)
	if err != nil {
		log.Error().Err(err).Msg("SecretHandler.Create")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ошибка создания секрета"})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// GetByID godoc
// @Summary Получить секрет по ID (с расшифровкой)
// @Tags secrets
// @Security BearerAuth
// @Produce json
// @Param id path string true "UUID секрета"
// @Success 200 {object} domain.SecretResponse
// @Failure 400,401,403,404,500 {object} ErrorResponse
// @Router /api/v1/secrets/{id} [get]
func (h *SecretHandler) GetByID(c *gin.Context) {
	claims := middleware.GetClaims(c)

	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	resp, err := h.secretSvc.GetByID(c.Request.Context(), claims.UserID, claims.RoleName, id)
	if err != nil {
		h.handleSecretError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// List godoc
// @Summary Список секретов (только свои для user, все для admin/manager)
// @Tags secrets
// @Security BearerAuth
// @Produce json
// @Param limit  query int false "Лимит записей (по умолчанию 20)"
// @Param offset query int false "Смещение"
// @Success 200 {object} PaginatedResponse
// @Router /api/v1/secrets [get]
func (h *SecretHandler) List(c *gin.Context) {
	claims := middleware.GetClaims(c)
	limit, offset := parsePagination(c)

	items, total, err := h.secretSvc.List(c.Request.Context(), claims.UserID, claims.RoleName, limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("SecretHandler.List")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ошибка получения секретов"})
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// Update godoc
// @Summary Обновить секрет
// @Tags secrets
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id   path string                       true "UUID секрета"
// @Param body body domain.UpdateSecretRequest   true "Новые данные"
// @Success 200 {object} domain.SecretResponse
// @Failure 400,401,403,404,500 {object} ErrorResponse
// @Router /api/v1/secrets/{id} [put]
func (h *SecretHandler) Update(c *gin.Context) {
	claims := middleware.GetClaims(c)

	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	var req domain.UpdateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	resp, err := h.secretSvc.Update(c.Request.Context(), claims.UserID, id, req)
	if err != nil {
		h.handleSecretError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Delete godoc
// @Summary Удалить секрет
// @Tags secrets
// @Security BearerAuth
// @Param id path string true "UUID секрета"
// @Success 204
// @Failure 400,401,403,404,500 {object} ErrorResponse
// @Router /api/v1/secrets/{id} [delete]
func (h *SecretHandler) Delete(c *gin.Context) {
	claims := middleware.GetClaims(c)

	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	if err := h.secretSvc.Delete(c.Request.Context(), claims.UserID, claims.RoleName, id); err != nil {
		h.handleSecretError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (h *SecretHandler) handleSecretError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, pgRepo.ErrSecretNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "секрет не найден"})
	case errors.Is(err, pgRepo.ErrSecretForbidden):
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "доступ запрещён"})
	default:
		log.Error().Err(err).Msg("SecretHandler: внутренняя ошибка")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "внутренняя ошибка сервера"})
	}
}

// parseUUID извлекает и парсит параметр пути как UUID.
func parseUUID(c *gin.Context, param string) (uuid.UUID, error) {
	raw := c.Param(param)
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "неверный формат UUID: " + raw})
		return uuid.Nil, err
	}
	return id, nil
}

// parsePagination извлекает limit и offset из query-параметров.
func parsePagination(c *gin.Context) (limit, offset int) {
	limit = 20
	offset = 0

	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}
