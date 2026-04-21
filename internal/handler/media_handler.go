// Package handler реализует HTTP-хендлеры для загрузки и скачивания
// зашифрованных медиа-файлов.
package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/securestorage/internal/middleware"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
	"github.com/yourusername/securestorage/internal/service"
)

// MediaHandler — хендлер управления медиа-объектами.
type MediaHandler struct {
	mediaSvc  service.MediaService
	maxUpload int64 // максимальный размер загрузки в байтах
}

// NewMediaHandler создаёт новый MediaHandler.
func NewMediaHandler(mediaSvc service.MediaService, maxUpload int64) *MediaHandler {
	return &MediaHandler{mediaSvc: mediaSvc, maxUpload: maxUpload}
}

// Upload godoc
// @Summary Загрузить медиа-файл (multipart/form-data)
// @Tags media
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Файл для загрузки"
// @Success 201 {object} domain.MediaUploadResponse
// @Failure 400,401,413,500 {object} ErrorResponse
// @Router /api/v1/media/upload [post]
func (h *MediaHandler) Upload(c *gin.Context) {
	claims := middleware.GetClaims(c)

	// Ограничиваем размер запроса
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.maxUpload)

	fileHeader, err := c.FormFile("file")
	if err != nil {
		if isRequestTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, ErrorResponse{
				Error: fmt.Sprintf("файл превышает максимальный допустимый размер (%d байт)", h.maxUpload),
			})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "ошибка получения файла: " + err.Error()})
		return
	}

	// Открываем файл
	src, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ошибка открытия файла"})
		return
	}
	defer src.Close()

	// Определяем Content-Type
	contentType := fileHeader.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	resp, err := h.mediaSvc.Upload(
		c.Request.Context(),
		claims.UserID,
		fileHeader.Filename,
		contentType,
		src,
		fileHeader.Size,
	)
	if err != nil {
		log.Error().Err(err).Str("filename", fileHeader.Filename).Msg("MediaHandler.Upload")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ошибка загрузки файла"})
		return
	}

	log.Info().
		Str("media_id", resp.ID.String()).
		Str("filename", resp.Filename).
		Str("owner", claims.UserID.String()).
		Msg("Медиа-файл загружен и зашифрован")

	c.JSON(http.StatusCreated, resp)
}

// Download godoc
// @Summary Скачать медиа-файл (дешифрование на лету)
// @Tags media
// @Security BearerAuth
// @Produce application/octet-stream
// @Param id path string true "UUID медиа-объекта"
// @Success 200 {file} binary
// @Failure 400,401,403,404,500 {object} ErrorResponse
// @Router /api/v1/media/{id}/download [get]
func (h *MediaHandler) Download(c *gin.Context) {
	claims := middleware.GetClaims(c)

	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	meta, data, err := h.mediaSvc.Download(c.Request.Context(), claims.UserID, claims.RoleName, id)
	if err != nil {
		h.handleMediaError(c, err)
		return
	}

	// Отдаём файл с оригинальным именем и content-type
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, meta.Filename))
	c.Header("Content-Type", meta.ContentType)
	c.Header("Content-Length", fmt.Sprintf("%d", len(data)))
	c.Data(http.StatusOK, meta.ContentType, data)
}

// List godoc
// @Summary Список медиа-объектов
// @Tags media
// @Security BearerAuth
// @Produce json
// @Param limit  query int false "Лимит"
// @Param offset query int false "Смещение"
// @Success 200 {object} PaginatedResponse
// @Router /api/v1/media [get]
func (h *MediaHandler) List(c *gin.Context) {
	claims := middleware.GetClaims(c)
	limit, offset := parsePagination(c)

	items, total, err := h.mediaSvc.List(c.Request.Context(), claims.UserID, claims.RoleName, limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("MediaHandler.List")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ошибка получения списка"})
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// Delete godoc
// @Summary Удалить медиа-объект
// @Tags media
// @Security BearerAuth
// @Param id path string true "UUID медиа-объекта"
// @Success 204
// @Failure 400,401,403,404,500 {object} ErrorResponse
// @Router /api/v1/media/{id} [delete]
func (h *MediaHandler) Delete(c *gin.Context) {
	claims := middleware.GetClaims(c)

	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	if err := h.mediaSvc.Delete(c.Request.Context(), claims.UserID, claims.RoleName, id); err != nil {
		h.handleMediaError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (h *MediaHandler) handleMediaError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, pgRepo.ErrMediaNotFound):
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "медиа-объект не найден"})
	default:
		msg := err.Error()
		if strings.Contains(msg, "доступ запрещён") {
			c.JSON(http.StatusForbidden, ErrorResponse{Error: "доступ запрещён"})
			return
		}
		log.Error().Err(err).Msg("MediaHandler: внутренняя ошибка")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "внутренняя ошибка сервера"})
	}
}

func isRequestTooLarge(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "http: request body too large")
}
