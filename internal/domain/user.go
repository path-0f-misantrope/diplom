// Package domain содержит доменные модели пользователей, ролей и разрешений.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// Permission — атомарное право доступа к ресурсу.
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description,omitempty"`
}

// Role — роль пользователя в RBAC-системе.
type Role struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}

// User — зарегистрированный пользователь системы.
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // никогда не отдаём клиенту
	RoleID       uuid.UUID `json:"role_id"`
	Role         *Role     `json:"role,omitempty"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ─── DTO ─────────────────────────────────────────────────────────────────────

// RegisterRequest — тело запроса при регистрации.
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=64,alphanum"`
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=128"`
}

// LoginRequest — тело запроса при входе.
type LoginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TokenPair — пара JWT-токенов: access и refresh.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshRequest — тело запроса обновления токена.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// UserResponse — публичный профиль пользователя.
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// ToResponse конвертирует User в публичное представление.
func (u *User) ToResponse() UserResponse {
	roleName := ""
	if u.Role != nil {
		roleName = u.Role.Name
	}
	return UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		Role:      roleName,
		IsActive:  u.IsActive,
		CreatedAt: u.CreatedAt,
	}
}

// UpdateRoleRequest — смена роли пользователя администратором.
type UpdateRoleRequest struct {
	RoleName string `json:"role_name" binding:"required,oneof=admin manager user"`
}

// Claims — данные внутри JWT-токена.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	RoleID   uuid.UUID `json:"role_id"`
	RoleName string    `json:"role_name"`
	TokenID  string    `json:"jti"` // уникальный идентификатор токена для инвалидации
}
