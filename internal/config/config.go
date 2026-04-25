// Package config загружает и валидирует конфигурацию приложения из
// переменных окружения и .env файла с помощью godotenv.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config — корневая структура конфигурации приложения.
type Config struct {
	App    AppConfig
	DB     DBConfig
	Redis  RedisConfig
	MinIO  MinIOConfig
	JWT    JWTConfig
	Crypto CryptoConfig
	Upload UploadConfig
}

// AppConfig — параметры HTTP-сервера.
type AppConfig struct {
	Env      string // development | production
	Port     int
	LogLevel string // debug | info | warn | error
}

// DBConfig — параметры подключения к PostgreSQL.
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
	MaxConns int32
	MinConns int32
}

// DSN возвращает строку подключения к PostgreSQL.
func (c DBConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s pool_max_conns=%d pool_min_conns=%d",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode, c.MaxConns, c.MinConns,
	)
}

// RedisConfig — параметры подключения к Redis.
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

// MinIOConfig — параметры подключения к MinIO.
type MinIOConfig struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	UseSSL    bool
	Bucket    string
}

// JWTConfig — настройки JSON Web Tokens.
type JWTConfig struct {
	Secret     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// CryptoConfig — настройки шифрования.
type CryptoConfig struct {
	// EncryptionKey — hex-строка 32 байта (256 бит) для AES-256-GCM.
	EncryptionKey string
}

// UploadConfig — ограничения для загружаемых файлов.
type UploadConfig struct {
	MaxSize int64 // байты
}

// Load читает конфигурацию из переменных среды / .env файла.
func Load() (*Config, error) {
	// Загружаем .env файл в переменные окружения OS.
	// Ошибку игнорируем, так как в production среде файла .env может не быть,
	// и переменные будут заданы на уровне системы (например, через Docker).
	// Загружаем .env файл. Сначала пробуем в текущей директории, 
	// затем в корне проекта (если запускаем из cmd/server).
	_ = godotenv.Load(".env")
	_ = godotenv.Load("../../.env")

	// Парсим длительности JWT
	accessTTL, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("config: неверный JWT_ACCESS_TTL: %w", err)
	}

	refreshTTL, err := time.ParseDuration(getEnv("JWT_REFRESH_TTL", "168h")) // 7 дней
	if err != nil {
		return nil, fmt.Errorf("config: неверный JWT_REFRESH_TTL: %w", err)
	}

	cfg := &Config{
		App: AppConfig{
			Env:      getEnv("APP_ENV", "development"),
			Port:     getEnvAsInt("APP_PORT", 8080),
			LogLevel: getEnv("APP_LOG_LEVEL", "info"),
		},
		DB: DBConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvAsInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", ""),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", ""),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
			MaxConns: int32(getEnvAsInt("DB_MAX_CONNS", 25)),
			MinConns: int32(getEnvAsInt("DB_MIN_CONNS", 5)),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", ""),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},
		MinIO: MinIOConfig{
			Endpoint:  getEnv("MINIO_ENDPOINT", ""),
			AccessKey: getEnv("MINIO_ACCESS_KEY", ""),
			SecretKey: getEnv("MINIO_SECRET_KEY", ""),
			UseSSL:    getEnvAsBool("MINIO_USE_SSL", false),
			Bucket:    getEnv("MINIO_BUCKET", "secure-media"),
		},
		JWT: JWTConfig{
			Secret:     getEnv("JWT_SECRET", ""),
			AccessTTL:  accessTTL,
			RefreshTTL: refreshTTL,
		},
		Crypto: CryptoConfig{
			EncryptionKey: getEnv("APP_ENCRYPTION_KEY", ""),
		},
		Upload: UploadConfig{
			MaxSize: getEnvAsInt64("UPLOAD_MAX_SIZE", 104857600), // 100MB
		},
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate проверяет, что все обязательные поля заполнены.
func validate(cfg *Config) error {
	if cfg.DB.User == "" {
		return fmt.Errorf("config: DB_USER не задан")
	}
	if cfg.DB.Password == "" {
		return fmt.Errorf("config: DB_PASSWORD не задан")
	}
	if cfg.DB.Name == "" {
		return fmt.Errorf("config: DB_NAME не задан")
	}
	if cfg.JWT.Secret == "" {
		return fmt.Errorf("config: JWT_SECRET не задан")
	}
	if cfg.Crypto.EncryptionKey == "" {
		return fmt.Errorf("config: APP_ENCRYPTION_KEY не задан")
	}
	if len(cfg.Crypto.EncryptionKey) != 64 {
		return fmt.Errorf("config: APP_ENCRYPTION_KEY должен быть 64 hex-символа (32 байта)")
	}
	if cfg.MinIO.AccessKey == "" || cfg.MinIO.SecretKey == "" {
		return fmt.Errorf("config: MINIO_ACCESS_KEY и MINIO_SECRET_KEY не заданы")
	}
	return nil
}

// --- Вспомогательные функции для чтения переменных окружения ---

// getEnv читает переменную окружения или возвращает значение по умолчанию.
func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

// getEnvAsInt читает переменную окружения как int или возвращает defaultVal.
func getEnvAsInt(key string, defaultVal int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultVal
}

// getEnvAsInt64 читает переменную окружения как int64 или возвращает defaultVal.
func getEnvAsInt64(key string, defaultVal int64) int64 {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseInt(valueStr, 10, 64); err == nil {
		return value
	}
	return defaultVal
}

// getEnvAsBool читает переменную окружения как bool или возвращает defaultVal.
func getEnvAsBool(key string, defaultVal bool) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultVal
}
