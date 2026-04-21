// Package domain — модель зашифрованного медиа-объекта.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// MediaObject — зашифрованный файл, хранящийся в MinIO.
// Сам файл в MinIO зашифрован AES-256-GCM; метаданные — в PostgreSQL.
type MediaObject struct {
	ID          uuid.UUID `json:"id"`
	OwnerID     uuid.UUID `json:"owner_id"`
	Filename    string    `json:"filename"`    // оригинальное имя файла
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`  // размер оригинала до шифрования
	BucketName  string    `json:"-"`           // внутренний MinIO bucket
	ObjectKey   string    `json:"-"`           // UUID-ключ объекта в MinIO
	IV          string    `json:"-"`           // base64 nonce для дешифровки
	CreatedAt   time.Time `json:"created_at"`
}

// ─── DTO ─────────────────────────────────────────────────────────────────────

// MediaUploadResponse — ответ после успешной загрузки.
type MediaUploadResponse struct {
	ID          uuid.UUID `json:"id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	CreatedAt   time.Time `json:"created_at"`
}

// MediaListItem — краткое описание медиа-объекта в списке.
type MediaListItem struct {
	ID          uuid.UUID `json:"id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	CreatedAt   time.Time `json:"created_at"`
}

// ToUploadResponse конвертирует MediaObject в ответ API.
func (m *MediaObject) ToUploadResponse() MediaUploadResponse {
	return MediaUploadResponse{
		ID:          m.ID,
		Filename:    m.Filename,
		ContentType: m.ContentType,
		SizeBytes:   m.SizeBytes,
		CreatedAt:   m.CreatedAt,
	}
}

// ToListItem конвертирует MediaObject в краткое представление.
func (m *MediaObject) ToListItem() MediaListItem {
	return MediaListItem{
		ID:          m.ID,
		Filename:    m.Filename,
		ContentType: m.ContentType,
		SizeBytes:   m.SizeBytes,
		CreatedAt:   m.CreatedAt,
	}
}
