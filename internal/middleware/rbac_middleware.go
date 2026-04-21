// Package middleware — RBAC middleware для проверки прав доступа в Gin.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/securestorage/internal/service"
)

// RequirePermission возвращает middleware, проверяющий наличие
// разрешения resource:action у текущего пользователя.
//
// Должен применяться ПОСЛЕ Auth middleware.
func RequirePermission(rbacSvc service.RBACService, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := GetClaims(c)
		if claims == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "не аутентифицирован",
			})
			return
		}

		allowed, err := rbacSvc.HasPermission(c.Request.Context(), claims.RoleID, resource, action)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "ошибка проверки прав доступа",
			})
			return
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":    "доступ запрещён",
				"required": resource + ":" + action,
				"role":     claims.RoleName,
			})
			return
		}

		c.Next()
	}
}

// RequireRole возвращает middleware проверки конкретной роли.
func RequireRole(roles ...string) gin.HandlerFunc {
	roleSet := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		roleSet[r] = struct{}{}
	}

	return func(c *gin.Context) {
		claims := GetClaims(c)
		if claims == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "не аутентифицирован",
			})
			return
		}

		if _, ok := roleSet[claims.RoleName]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "недостаточно прав",
			})
			return
		}

		c.Next()
	}
}
