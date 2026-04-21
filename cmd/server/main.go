// Точка входа системы безопасного хранения конфиденциальных данных.
//
// Порядок инициализации:
//  1. Загрузка конфигурации (viper + .env)
//  2. Инициализация logger (zerolog)
//  3. Подключение к PostgreSQL (pgxpool) + миграции
//  4. Подключение к Redis
//  5. Подключение к MinIO + создание bucket
//  6. Инициализация Cipher (AES-256-GCM)
//  7. Сборка репозиториев, сервисов и хендлеров
//  8. Настройка Gin роутера
//  9. Graceful shutdown
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/yourusername/securestorage/internal/config"
	"github.com/yourusername/securestorage/internal/crypto"
	"github.com/yourusername/securestorage/internal/handler"
	"github.com/yourusername/securestorage/internal/middleware"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
	redisRepo "github.com/yourusername/securestorage/internal/repository/redis"
	"github.com/yourusername/securestorage/internal/service"
	"github.com/yourusername/securestorage/internal/storage"
)

func main() {
	// ── 1. Конфигурация ───────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: config: %v\n", err)
		os.Exit(1)
	}

	// ── 2. Logger ─────────────────────────────────────────────────────────────
	initLogger(cfg.App.LogLevel, cfg.App.Env)

	log.Info().
		Str("env", cfg.App.Env).
		Int("port", cfg.App.Port).
		Msg("Запуск сервера")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── 3. PostgreSQL ─────────────────────────────────────────────────────────
	pool, err := initPostgres(ctx, cfg.DB)
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось подключиться к PostgreSQL")
	}
	defer pool.Close()

	// Применяем миграции
	if err := runMigrations(cfg.DB); err != nil {
		log.Fatal().Err(err).Msg("Миграция БД завершилась с ошибкой")
	}

	// ── 4. Redis ──────────────────────────────────────────────────────────────
	redisClient, err := initRedis(ctx, cfg.Redis)
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось подключиться к Redis")
	}
	defer redisClient.Close()

	// ── 5. MinIO ──────────────────────────────────────────────────────────────
	minioClient, err := storage.NewMinIOClient(ctx, cfg.MinIO)
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось подключиться к MinIO")
	}

	// ── 6. AES-256-GCM Cipher ─────────────────────────────────────────────────
	keyBytes, err := hex.DecodeString(cfg.Crypto.EncryptionKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Неверный формат ключа шифрования (ожидается hex)")
	}
	cipher, err := crypto.NewCipher(keyBytes)
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось инициализировать cipher")
	}

	// ── 7. Репозитории ────────────────────────────────────────────────────────
	userRepo    := pgRepo.NewUserRepository(pool)
	secretRepo  := pgRepo.NewSecretRepository(pool)
	mediaRepo   := pgRepo.NewMediaRepository(pool)
	sessionRepo := redisRepo.NewSessionRepository(redisClient)

	// ── 8. Сервисы ────────────────────────────────────────────────────────────
	authSvc   := service.NewAuthService(userRepo, sessionRepo, cfg.JWT)
	rbacSvc   := service.NewRBACService(userRepo)
	secretSvc := service.NewSecretService(secretRepo, cipher)
	mediaSvc  := service.NewMediaService(mediaRepo, minioClient, cipher)

	// ── 9. Хендлеры ───────────────────────────────────────────────────────────
	authH   := handler.NewAuthHandler(authSvc, cfg.JWT)
	secretH := handler.NewSecretHandler(secretSvc)
	mediaH  := handler.NewMediaHandler(mediaSvc, cfg.Upload.MaxSize)

	// ── 10. Gin роутер ────────────────────────────────────────────────────────
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := setupRouter(authH, secretH, mediaH, authSvc, rbacSvc)

	// ── 11. HTTP сервер с Graceful Shutdown ───────────────────────────────────
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.App.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Запускаем сервер в горутине
	go func() {
		log.Info().Str("addr", srv.Addr).Msg("HTTP-сервер запущен")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("HTTP-сервер завершился с ошибкой")
		}
	}()

	// Ожидаем сигнал завершения
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Получен сигнал завершения, graceful shutdown...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Ошибка при завершении HTTP-сервера")
	}

	log.Info().Msg("Сервер остановлен")
}

// ─── setupRouter настраивает все маршруты приложения ─────────────────────────

func setupRouter(
	authH   *handler.AuthHandler,
	secretH *handler.SecretHandler,
	mediaH  *handler.MediaHandler,
	authSvc service.AuthService,
	rbacSvc service.RBACService,
) *gin.Engine {
	r := gin.New()

	// Глобальные middleware
	r.Use(gin.Recovery())
	r.Use(requestLogger())
	r.Use(middleware.CORS())

	// Health-check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
	})

	api := r.Group("/api/v1")

	// ── Auth (публичные маршруты) ─────────────────────────────────────────────
	auth := api.Group("/auth")
	{
		auth.POST("/register", authH.Register)
		auth.POST("/login",    authH.Login)
		auth.POST("/refresh",  authH.Refresh)

		// Logout и /me требуют аутентификации
		authProtected := auth.Group("", middleware.Auth(authSvc))
		{
			authProtected.POST("/logout", authH.Logout)
			authProtected.GET("/me",      authH.Me)
		}
	}

	// ── Защищённые маршруты ───────────────────────────────────────────────────
	protected := api.Group("", middleware.Auth(authSvc))

	// Secrets
	secrets := protected.Group("/secrets")
	{
		secrets.POST("",    middleware.RequirePermission(rbacSvc, "secrets", "create"), secretH.Create)
		secrets.GET("",     middleware.RequirePermission(rbacSvc, "secrets", "read"),   secretH.List)
		secrets.GET("/:id", middleware.RequirePermission(rbacSvc, "secrets", "read"),   secretH.GetByID)
		secrets.PUT("/:id", middleware.RequirePermission(rbacSvc, "secrets", "update"), secretH.Update)
		secrets.DELETE("/:id", middleware.RequirePermission(rbacSvc, "secrets", "delete"), secretH.Delete)
	}

	// Media
	media := protected.Group("/media")
	{
		media.POST("/upload",       middleware.RequirePermission(rbacSvc, "media", "upload"),   mediaH.Upload)
		media.GET("",               middleware.RequirePermission(rbacSvc, "media", "download"), mediaH.List)
		media.GET("/:id/download",  middleware.RequirePermission(rbacSvc, "media", "download"), mediaH.Download)
		media.DELETE("/:id",        middleware.RequirePermission(rbacSvc, "media", "delete"),   mediaH.Delete)
	}

	// Admin — управление пользователями (только admin)
	admin := protected.Group("/admin", middleware.RequireRole("admin"))
	{
		admin.GET("/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin: список пользователей (TODO)"})
		})
	}

	return r
}

// ─── initLogger настраивает zerolog ──────────────────────────────────────────

func initLogger(level, env string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	if env != "production" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	} else {
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	}
}

// ─── requestLogger — middleware логирования HTTP-запросов ─────────────────────

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		event := log.Info()
		if status >= 500 {
			event = log.Error()
		} else if status >= 400 {
			event = log.Warn()
		}

		event.
			Int("status", status).
			Str("method", c.Request.Method).
			Str("path", path).
			Str("ip", c.ClientIP()).
			Dur("latency", latency).
			Msg("HTTP-запрос")
	}
}

// ─── initPostgres подключается к PostgreSQL через pgxpool ────────────────────

func initPostgres(ctx context.Context, cfg config.DBConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("postgres: парсинг DSN: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: создание пула: %w", err)
	}

	// Проверяем соединение
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("db", cfg.Name).
		Msg("PostgreSQL: подключение установлено")

	return pool, nil
}

// ─── initRedis подключается к Redis ──────────────────────────────────────────

func initRedis(ctx context.Context, cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis: ping: %w", err)
	}

	log.Info().Str("addr", cfg.Addr).Msg("Redis: подключение установлено")
	return client, nil
}

// ─── runMigrations выполняет SQL-миграции ────────────────────────────────────

func runMigrations(cfg config.DBConfig) error {
	// DSN для migrate (без pgx pool параметров)
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name, cfg.SSLMode,
	)

	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		return fmt.Errorf("migrate: инициализация: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Info().Msg("Миграции: нет изменений")
			return nil
		}
		return fmt.Errorf("migrate: применение: %w", err)
	}

	log.Info().Msg("Миграции: успешно применены")
	return nil
}
