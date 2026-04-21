// Package redis реализует управление сессиями и инвалидацию токенов через Redis.
package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// Префикс ключей для refresh токенов
	refreshTokenPrefix = "refresh:"
	// Префикс ключей для блок-листа access токенов
	blacklistPrefix = "blacklist:"
)

// SessionRepository — интерфейс управления сессиями.
type SessionRepository interface {
	// StoreRefreshToken сохраняет refresh token с TTL.
	StoreRefreshToken(ctx context.Context, tokenID, userID string, ttl time.Duration) error
	// GetRefreshToken возвращает userID по tokenID. Ошибка если не найден или истёк.
	GetRefreshToken(ctx context.Context, tokenID string) (string, error)
	// DeleteRefreshToken удаляет refresh token (logout / ротация).
	DeleteRefreshToken(ctx context.Context, tokenID string) error
	// BlacklistAccessToken добавляет access token в чёрный список.
	BlacklistAccessToken(ctx context.Context, jti string, ttl time.Duration) error
	// IsBlacklisted проверяет, находится ли токен в чёрном списке.
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
}

// sessionRepo — реализация SessionRepository.
type sessionRepo struct {
	client *redis.Client
}

// NewSessionRepository создаёт новый sessionRepo.
func NewSessionRepository(client *redis.Client) SessionRepository {
	return &sessionRepo{client: client}
}

// StoreRefreshToken сохраняет refresh token (tokenID → userID) в Redis.
func (r *sessionRepo) StoreRefreshToken(
	ctx context.Context,
	tokenID, userID string,
	ttl time.Duration,
) error {
	key := refreshTokenPrefix + tokenID
	if err := r.client.Set(ctx, key, userID, ttl).Err(); err != nil {
		return fmt.Errorf("session: сохранение refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken возвращает userID по tokenID refresh токена.
func (r *sessionRepo) GetRefreshToken(ctx context.Context, tokenID string) (string, error) {
	key := refreshTokenPrefix + tokenID
	userID, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("session: refresh token не найден или истёк")
	}
	if err != nil {
		return "", fmt.Errorf("session: получение refresh token: %w", err)
	}
	return userID, nil
}

// DeleteRefreshToken удаляет refresh token из Redis.
func (r *sessionRepo) DeleteRefreshToken(ctx context.Context, tokenID string) error {
	key := refreshTokenPrefix + tokenID
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("session: удаление refresh token: %w", err)
	}
	return nil
}

// BlacklistAccessToken помещает JTI access-токена в чёрный список.
// TTL должен совпадать с оставшимся временем жизни токена.
func (r *sessionRepo) BlacklistAccessToken(ctx context.Context, jti string, ttl time.Duration) error {
	key := blacklistPrefix + jti
	if err := r.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("session: добавление в blacklist: %w", err)
	}
	return nil
}

// IsBlacklisted проверяет наличие JTI в чёрном списке.
func (r *sessionRepo) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := blacklistPrefix + jti
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("session: проверка blacklist: %w", err)
	}
	return exists > 0, nil
}
