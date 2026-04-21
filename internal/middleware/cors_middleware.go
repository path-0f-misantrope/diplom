package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS настроен для работы с локальным фронтендом (Vite по умолчанию использует 5173).
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		// В продакшене здесь должен быть строго определенный список allowed origins.
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin) // Разрешаем запросы с любого Origin (т.к. у нас локальная разработка)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		// Разрешаем передачу заголовков Authorization для JWT и Content-Type для JSON/FormData
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
