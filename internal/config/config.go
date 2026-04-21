// Package config загружает и валидирует конфигурацию приложения из
// переменных окружения и .env файла с помощью viper.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config — корневая структура конфигурации приложения.
type Config struct {
	App      AppConfig
	DB       DBConfig
	Redis    RedisConfig
	MinIO    MinIOConfig
	JWT      JWTConfig
	Crypto   CryptoConfig
	Upload   UploadConfig
}

// AppConfig — параметры HTTP-сервера.
type AppConfig struct {
	Env       string // development | production
	Port      int
	LogLevel  string // debug | info | warn | error
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
// Переменные окружения имеют приоритет над .env.
func Load() (*Config, error) {
	v := viper.New()

	// Значения по умолчанию
	v.SetDefault("app.env", "development")
	v.SetDefault("app.port", 8080)
	v.SetDefault("app.log_level", "info")

	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5432)
	v.SetDefault("db.sslmode", "disable")
	v.SetDefault("db.max_conns", 25)
	v.SetDefault("db.min_conns", 5)

	v.SetDefault("redis.db", 0)

	v.SetDefault("minio.use_ssl", false)
	v.SetDefault("minio.bucket", "secure-media")

	v.SetDefault("jwt.access_ttl", "15m")
	v.SetDefault("jwt.refresh_ttl", "168h") // 7 дней

	v.SetDefault("upload.max_size", 104857600) // 100MB

	// Загружаем .env файл (если присутствует)
	v.SetConfigName(".env")
	v.SetConfigType("env")
	v.AddConfigPath(".")
	_ = v.ReadInConfig() // Ошибка игнорируется — .env необязателен

	// Читаем из переменных окружения
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Парсим длительности JWT
	accessTTL, err := time.ParseDuration(v.GetString("jwt.access_ttl"))
	if err != nil {
		return nil, fmt.Errorf("config: неверный JWT_ACCESS_TTL: %w", err)
	}

	refreshTTL, err := time.ParseDuration(v.GetString("jwt.refresh_ttl"))
	if err != nil {
		return nil, fmt.Errorf("config: неверный JWT_REFRESH_TTL: %w", err)
	}

	cfg := &Config{
		App: AppConfig{
			Env:      v.GetString("app.env"),
			Port:     v.GetInt("app.port"),
			LogLevel: v.GetString("app.log_level"),
		},
		DB: DBConfig{
			Host:     v.GetString("db.host"),
			Port:     v.GetInt("db.port"),
			User:     v.GetString("db.user"),
			Password: v.GetString("db.password"),
			Name:     v.GetString("db.name"),
			SSLMode:  v.GetString("db.sslmode"),
			MaxConns: int32(v.GetInt("db.max_conns")),
			MinConns: int32(v.GetInt("db.min_conns")),
		},
		Redis: RedisConfig{
			Addr:     v.GetString("redis.addr"),
			Password: v.GetString("redis.password"),
			DB:       v.GetInt("redis.db"),
		},
		MinIO: MinIOConfig{
			Endpoint:  v.GetString("minio.endpoint"),
			AccessKey: v.GetString("minio.access_key"),
			SecretKey: v.GetString("minio.secret_key"),
			UseSSL:    v.GetBool("minio.use_ssl"),
			Bucket:    v.GetString("minio.bucket"),
		},
		JWT: JWTConfig{
			Secret:     v.GetString("jwt.secret"),
			AccessTTL:  accessTTL,
			RefreshTTL: refreshTTL,
		},
		Crypto: CryptoConfig{
			EncryptionKey: v.GetString("app.encryption_key"),
		},
		Upload: UploadConfig{
			MaxSize: v.GetInt64("upload.max_size"),
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
