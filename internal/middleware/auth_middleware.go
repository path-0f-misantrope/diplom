// Package middleware реализует JWT-аутентификацию для Gin.
// Middleware извлекает токен из заголовка Authorization,
// валидирует его и кладёт Claims в контекст запроса.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/securestorage/internal/domain"
	"github.com/yourusername/securestorage/internal/service"
)

const (
	// ContextKeyClaims — ключ для хранения Claims в gin.Context.
	ContextKeyClaims = "claims"
)

// Auth возвращает middleware аутентификации по JWT Bearer-токену.
func Auth(authSvc service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Извлекаем заголовок
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "отсутствует заголовок Authorization",
			})
			return
		}

		// Формат: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "неверный формат токена (ожидается: Bearer <token>)",
			})
			return
		}

		tokenStr := parts[1]

		// Валидируем токен (включая проверку blacklist в Redis)
		claims, err := authSvc.ValidateAccessToken(c.Request.Context(), tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "невалидный или истёкший токен",
			})
			return
		}

		// Сохраняем claims и raw-токен в контексте для использования в хендлерах
		c.Set(ContextKeyClaims, claims)
		c.Set("raw_token", tokenStr)
		c.Next()
	}
}

// GetClaims извлекает Claims из контекста Gin.
// Возвращает nil если claims отсутствуют (не аутентифицирован).
func GetClaims(c *gin.Context) *domain.Claims {
	v, exists := c.Get(ContextKeyClaims)
	if !exists {
		return nil
	}
	claims, _ := v.(*domain.Claims)
	return claims
}
