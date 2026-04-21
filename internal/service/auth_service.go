// Package service реализует бизнес-логику аутентификации:
// регистрацию, логин, выдачу JWT-пар, рефреш и логаут.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/yourusername/securestorage/internal/config"
	"github.com/yourusername/securestorage/internal/domain"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
	redisRepo "github.com/yourusername/securestorage/internal/repository/redis"
)

// bcryptCost — стоимость хеширования пароля (рекомендуемый минимум — 12).
const bcryptCost = 12

// AuthService — интерфейс сервиса аутентификации.
type AuthService interface {
	Register(ctx context.Context, req domain.RegisterRequest) (*domain.User, error)
	Login(ctx context.Context, req domain.LoginRequest) (*domain.TokenPair, error)
	Logout(ctx context.Context, accessJTI, refreshTokenID string, accessTTL time.Duration) error
	Refresh(ctx context.Context, refreshToken string) (*domain.TokenPair, error)
	ValidateAccessToken(ctx context.Context, tokenStr string) (*domain.Claims, error)
}

// authService — реализация AuthService.
type authService struct {
	userRepo    pgRepo.UserRepository
	sessionRepo redisRepo.SessionRepository
	cfg         config.JWTConfig
}

// NewAuthService создаёт новый authService.
func NewAuthService(
	userRepo pgRepo.UserRepository,
	sessionRepo redisRepo.SessionRepository,
	cfg config.JWTConfig,
) AuthService {
	return &authService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		cfg:         cfg,
	}
}

// Register регистрирует нового пользователя с ролью "user".
func (s *authService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.User, error) {
	// Получаем роль "user" по умолчанию
	role, err := s.userRepo.GetRoleByName(ctx, "user")
	if err != nil {
		return nil, fmt.Errorf("authService.Register: получение роли: %w", err)
	}

	// Хешируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("authService.Register: хеширование пароля: %w", err)
	}

	user := &domain.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		RoleID:       role.ID,
		IsActive:     true,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err // ErrEmailExists / ErrUsernameExists пробрасываем как есть
	}

	log.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("Пользователь зарегистрирован")
	return user, nil
}

// Login проверяет учётные данные и возвращает пару токенов.
func (s *authService) Login(ctx context.Context, req domain.LoginRequest) (*domain.TokenPair, error) {
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, pgRepo.ErrUserNotFound) {
			return nil, fmt.Errorf("authService.Login: неверный email или пароль")
		}
		return nil, fmt.Errorf("authService.Login: %w", err)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("authService.Login: аккаунт заблокирован")
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("authService.Login: неверный email или пароль")
	}

	// Получаем роль с разрешениями
	role, err := s.userRepo.GetRoleWithPermissions(ctx, user.RoleID)
	if err != nil {
		return nil, fmt.Errorf("authService.Login: получение роли: %w", err)
	}
	user.Role = role

	return s.issueTokenPair(ctx, user)
}

// Logout инвалидирует access и refresh токены.
func (s *authService) Logout(
	ctx context.Context,
	accessJTI, refreshTokenID string,
	accessTTL time.Duration,
) error {
	// Добавляем access token в blacklist
	if err := s.sessionRepo.BlacklistAccessToken(ctx, accessJTI, accessTTL); err != nil {
		log.Warn().Err(err).Msg("Logout: не удалось добавить access token в blacklist")
	}

	// Удаляем refresh token
	if err := s.sessionRepo.DeleteRefreshToken(ctx, refreshTokenID); err != nil {
		log.Warn().Err(err).Msg("Logout: не удалось удалить refresh token")
	}

	return nil
}

// Refresh обменивает refresh token на новую пару токенов.
func (s *authService) Refresh(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	// Парсим refresh token
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("authService.Refresh: невалидный токен: %w", err)
	}

	// Проверяем наличие в Redis
	userIDStr, err := s.sessionRepo.GetRefreshToken(ctx, claims.TokenID)
	if err != nil {
		return nil, fmt.Errorf("authService.Refresh: токен не найден или истёк")
	}

	if userIDStr != claims.UserID.String() {
		return nil, fmt.Errorf("authService.Refresh: несоответствие пользователя")
	}

	// Удаляем старый refresh token (ротация)
	_ = s.sessionRepo.DeleteRefreshToken(ctx, claims.TokenID)

	// Загружаем пользователя
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("authService.Refresh: пользователь не найден: %w", err)
	}

	role, err := s.userRepo.GetRoleWithPermissions(ctx, user.RoleID)
	if err != nil {
		return nil, fmt.Errorf("authService.Refresh: роль не найдена: %w", err)
	}
	user.Role = role

	return s.issueTokenPair(ctx, user)
}

// ValidateAccessToken проверяет access token и возвращает Claims.
func (s *authService) ValidateAccessToken(ctx context.Context, tokenStr string) (*domain.Claims, error) {
	claims, err := s.parseToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("authService.ValidateAccessToken: %w", err)
	}

	// Проверяем blacklist
	blacklisted, err := s.sessionRepo.IsBlacklisted(ctx, claims.TokenID)
	if err != nil {
		log.Warn().Err(err).Msg("ValidateAccessToken: ошибка проверки blacklist")
	}
	if blacklisted {
		return nil, fmt.Errorf("authService.ValidateAccessToken: токен отозван")
	}

	return claims, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// jwtClaims — внутренняя структура полезной нагрузки JWT.
type jwtClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	RoleID   uuid.UUID `json:"role_id"`
	RoleName string    `json:"role_name"`
	TokenID  string    `json:"jti"`
	jwt.RegisteredClaims
}

// issueTokenPair генерирует access и refresh токены и сохраняет refresh в Redis.
func (s *authService) issueTokenPair(ctx context.Context, user *domain.User) (*domain.TokenPair, error) {
	roleName := ""
	if user.Role != nil {
		roleName = user.Role.Name
	}

	// Access token
	accessJTI := uuid.New().String()
	accessClaims := &jwtClaims{
		UserID:   user.ID,
		Username: user.Username,
		RoleID:   user.RoleID,
		RoleName: roleName,
		TokenID:  accessJTI,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID.String(),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessStr, err := accessToken.SignedString([]byte(s.cfg.Secret))
	if err != nil {
		return nil, fmt.Errorf("issueTokenPair: подпись access token: %w", err)
	}

	// Refresh token
	refreshJTI := uuid.New().String()
	refreshClaims := &jwtClaims{
		UserID:  user.ID,
		TokenID: refreshJTI,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.RefreshTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID.String(),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshStr, err := refreshToken.SignedString([]byte(s.cfg.Secret))
	if err != nil {
		return nil, fmt.Errorf("issueTokenPair: подпись refresh token: %w", err)
	}

	// Сохраняем refresh token в Redis
	if err := s.sessionRepo.StoreRefreshToken(ctx, refreshJTI, user.ID.String(), s.cfg.RefreshTTL); err != nil {
		return nil, fmt.Errorf("issueTokenPair: сохранение refresh token: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessStr,
		RefreshToken: refreshStr,
	}, nil
}

// parseToken разбирает и верифицирует JWT токен.
func (s *authService) parseToken(tokenStr string) (*domain.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный алгоритм подписи: %v", t.Header["alg"])
		}
		return []byte(s.cfg.Secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parseToken: %w", err)
	}

	jc, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("parseToken: невалидные claims")
	}

	return &domain.Claims{
		UserID:   jc.UserID,
		Username: jc.Username,
		RoleID:   jc.RoleID,
		RoleName: jc.RoleName,
		TokenID:  jc.TokenID,
	}, nil
}
