// Package handler реализует HTTP-хендлеры аутентификации.
package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/securestorage/internal/config"
	"github.com/yourusername/securestorage/internal/domain"
	"github.com/yourusername/securestorage/internal/middleware"
	"github.com/yourusername/securestorage/internal/service"
)

// AuthHandler — хендлер аутентификации.
type AuthHandler struct {
	authSvc service.AuthService
	jwtCfg  config.JWTConfig
}

// NewAuthHandler создаёт новый AuthHandler.
func NewAuthHandler(authSvc service.AuthService, jwtCfg config.JWTConfig) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, jwtCfg: jwtCfg}
}

// Register godoc
// @Summary Регистрация нового пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param body body domain.RegisterRequest true "Данные для регистрации"
// @Success 201 {object} domain.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req domain.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	user, err := h.authSvc.Register(c.Request.Context(), req)
	if err != nil {
		log.Warn().Err(err).Str("email", req.Email).Msg("Register: ошибка регистрации")
		status := http.StatusInternalServerError
		if isConflict(err) {
			status = http.StatusConflict
		}
		c.JSON(status, ErrorResponse{Error: err.Error()})
		return
	}

	log.Info().Str("user_id", user.ID.String()).Msg("Register: новый пользователь")
	c.JSON(http.StatusCreated, user.ToResponse())
}

// Login godoc
// @Summary Вход в систему
// @Tags auth
// @Accept json
// @Produce json
// @Param body body domain.LoginRequest true "Учётные данные"
// @Success 200 {object} domain.TokenPair
// @Failure 400,401 {object} ErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req domain.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	pair, err := h.authSvc.Login(c.Request.Context(), req)
	if err != nil {
		log.Warn().Err(err).Str("email", req.Email).Msg("Login: ошибка входа")
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "неверный email или пароль"})
		return
	}

	c.JSON(http.StatusOK, pair)
}

// Logout godoc
// @Summary Выход из системы (инвалидация токенов)
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body domain.RefreshRequest true "Refresh token"
// @Success 200 {object} MessageResponse
// @Failure 400,401 {object} ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "не аутентифицирован"})
		return
	}

	var req domain.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// TTL оставшегося времени жизни access token
	accessTTL := h.jwtCfg.AccessTTL

	if err := h.authSvc.Logout(
		c.Request.Context(),
		claims.TokenID,
		req.RefreshToken, // ID refresh токена (мы передаём сам токен — сервис его распарсит)
		accessTTL,
	); err != nil {
		log.Warn().Err(err).Msg("Logout: ошибка")
	}

	c.JSON(http.StatusOK, MessageResponse{Message: "вы вышли из системы"})
}

// Refresh godoc
// @Summary Обновление токенов
// @Tags auth
// @Accept json
// @Produce json
// @Param body body domain.RefreshRequest true "Refresh token"
// @Success 200 {object} domain.TokenPair
// @Failure 400,401 {object} ErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req domain.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	pair, err := h.authSvc.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		log.Warn().Err(err).Msg("Refresh: ошибка")
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "невалидный или истёкший refresh token"})
		return
	}

	c.JSON(http.StatusOK, pair)
}

// Me godoc
// @Summary Профиль текущего пользователя
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} domain.Claims
// @Router /api/v1/auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	claims := middleware.GetClaims(c)
	c.JSON(http.StatusOK, gin.H{
		"user_id":   claims.UserID,
		"username":  claims.Username,
		"role":      claims.RoleName,
		"token_exp": time.Now().Add(h.jwtCfg.AccessTTL),
	})
}

// ─── общие DTO ───────────────────────────────────────────────────────────────

// ErrorResponse — стандартный ответ с ошибкой.
type ErrorResponse struct {
	Error string `json:"error"`
}

// MessageResponse — стандартный ответ с сообщением.
type MessageResponse struct {
	Message string `json:"message"`
}

// PaginatedResponse — обёртка для списков с пагинацией.
type PaginatedResponse struct {
	Data   any   `json:"data"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// isConflict проверяет, является ли ошибка конфликтом уникальности.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "email уже зарегистрирован") ||
		strings.Contains(msg, "username уже занят")
}
