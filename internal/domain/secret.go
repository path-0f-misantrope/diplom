// Package domain — модель зашифрованного секрета.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// Secret — зашифрованная текстовая запись, хранящаяся в PostgreSQL.
// Поля EncryptedData и IV содержат base64-encoded шифротекст и nonce AES-256-GCM.
type Secret struct {
	ID            uuid.UUID `json:"id"`
	OwnerID       uuid.UUID `json:"owner_id"`
	Title         string    `json:"title"`
	EncryptedData string    `json:"-"` // не отдаём в чистом виде — только через сервис
	IV            string    `json:"-"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ─── DTO ─────────────────────────────────────────────────────────────────────

// CreateSecretRequest — тело запроса создания секрета.
type CreateSecretRequest struct {
	Title   string `json:"title"   binding:"required,min=1,max=255"`
	Payload string `json:"payload" binding:"required,min=1"` // открытый текст
}

// UpdateSecretRequest — тело запроса обновления секрета.
type UpdateSecretRequest struct {
	Title   string `json:"title"   binding:"omitempty,min=1,max=255"`
	Payload string `json:"payload" binding:"omitempty,min=1"`
}

// SecretResponse — ответ с расшифрованным содержимым.
type SecretResponse struct {
	ID        uuid.UUID `json:"id"`
	OwnerID   uuid.UUID `json:"owner_id"`
	Title     string    `json:"title"`
	Payload   string    `json:"payload"` // расшифрованный текст
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretListItem — краткое представление секрета в списке (без payload).
type SecretListItem struct {
	ID        uuid.UUID `json:"id"`
	OwnerID   uuid.UUID `json:"owner_id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
