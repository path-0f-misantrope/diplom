// Package service реализует бизнес-логику загрузки и скачивания
// зашифрованных медиа-файлов через MinIO.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/yourusername/securestorage/internal/crypto"
	"github.com/yourusername/securestorage/internal/domain"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
	"github.com/yourusername/securestorage/internal/storage"
)

// MediaService — интерфейс сервиса медиа.
type MediaService interface {
	Upload(ctx context.Context, ownerID uuid.UUID, filename, contentType string, src io.Reader, size int64) (*domain.MediaUploadResponse, error)
	Download(ctx context.Context, requesterID uuid.UUID, requesterRoleName string, id uuid.UUID) (*domain.MediaObject, []byte, error)
	List(ctx context.Context, requesterID uuid.UUID, requesterRoleName string, limit, offset int) ([]*domain.MediaListItem, int64, error)
	Delete(ctx context.Context, requesterID uuid.UUID, requesterRoleName string, id uuid.UUID) error
}

// mediaService — реализация MediaService.
type mediaService struct {
	repo   pgRepo.MediaRepository
	minio  *storage.MinIOClient
	cipher *crypto.Cipher
}

// NewMediaService создаёт новый mediaService.
func NewMediaService(
	repo pgRepo.MediaRepository,
	minio *storage.MinIOClient,
	cipher *crypto.Cipher,
) MediaService {
	return &mediaService{repo: repo, minio: minio, cipher: cipher}
}

// Upload шифрует файл и загружает в MinIO, сохраняет метаданные в PostgreSQL.
func (s *mediaService) Upload(
	ctx context.Context,
	ownerID uuid.UUID,
	filename, contentType string,
	src io.Reader,
	size int64,
) (*domain.MediaUploadResponse, error) {
	// Шифруем файл в буфер
	var encBuf bytes.Buffer
	ivB64, _, err := s.cipher.EncryptStream(src, &encBuf)
	if err != nil {
		return nil, fmt.Errorf("mediaService.Upload: шифрование: %w", err)
	}

	// Ключ объекта в MinIO — UUID, не раскрывает оригинальное имя
	objectKey := uuid.New().String()

	// Загружаем зашифрованный blob в MinIO
	// content-type храним как "application/octet-stream" — оригинальный тип не выводим
	if _, err := s.minio.PutObject(ctx, objectKey, encBuf.Bytes(), "application/octet-stream"); err != nil {
		return nil, fmt.Errorf("mediaService.Upload: MinIO PutObject: %w", err)
	}

	mediaObj := &domain.MediaObject{
		ID:          uuid.New(),
		OwnerID:     ownerID,
		Filename:    filename,
		ContentType: contentType,
		SizeBytes:   size,
		BucketName:  s.minio.BucketName,
		ObjectKey:   objectKey,
		IV:          ivB64,
	}

	if err := s.repo.Create(ctx, mediaObj); err != nil {
		// Откат: удаляем объект из MinIO если не удалось сохранить метаданные
		_ = s.minio.DeleteObject(ctx, objectKey)
		return nil, fmt.Errorf("mediaService.Upload: сохранение метаданных: %w", err)
	}

	resp := mediaObj.ToUploadResponse()
	return &resp, nil
}

// Download скачивает и дешифрует медиа-файл.
func (s *mediaService) Download(
	ctx context.Context,
	requesterID uuid.UUID,
	requesterRoleName string,
	id uuid.UUID,
) (*domain.MediaObject, []byte, error) {
	// Получаем метаданные
	meta, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgRepo.ErrMediaNotFound) {
			return nil, nil, pgRepo.ErrMediaNotFound
		}
		return nil, nil, fmt.Errorf("mediaService.Download: метаданные: %w", err)
	}

	// Проверка доступа
	if !isPrivileged(requesterRoleName) && meta.OwnerID != requesterID {
		return nil, nil, fmt.Errorf("mediaService.Download: доступ запрещён")
	}

	// Скачиваем зашифрованный blob из MinIO
	encData, err := s.minio.GetObject(ctx, meta.ObjectKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mediaService.Download: MinIO GetObject: %w", err)
	}

	// Дешифруем
	var plainBuf bytes.Buffer
	if err := s.cipher.DecryptStream(bytes.NewReader(encData), &plainBuf, meta.IV); err != nil {
		return nil, nil, fmt.Errorf("mediaService.Download: дешифрование: %w", err)
	}

	return meta, plainBuf.Bytes(), nil
}

// List возвращает список медиа-объектов.
func (s *mediaService) List(
	ctx context.Context,
	requesterID uuid.UUID,
	requesterRoleName string,
	limit, offset int,
) ([]*domain.MediaListItem, int64, error) {
	var (
		objs  []*domain.MediaObject
		total int64
		err   error
	)

	if isPrivileged(requesterRoleName) {
		objs, total, err = s.repo.ListAll(ctx, limit, offset)
	} else {
		objs, total, err = s.repo.ListByOwner(ctx, requesterID, limit, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("mediaService.List: %w", err)
	}

	items := make([]*domain.MediaListItem, 0, len(objs))
	for _, o := range objs {
		item := o.ToListItem()
		items = append(items, &item)
	}

	return items, total, nil
}

// Delete удаляет медиа-объект из MinIO и PostgreSQL.
func (s *mediaService) Delete(
	ctx context.Context,
	requesterID uuid.UUID,
	requesterRoleName string,
	id uuid.UUID,
) error {
	meta, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("mediaService.Delete: %w", err)
	}

	if !isPrivileged(requesterRoleName) && meta.OwnerID != requesterID {
		return fmt.Errorf("mediaService.Delete: доступ запрещён")
	}

	// Удаляем из MinIO
	if err := s.minio.DeleteObject(ctx, meta.ObjectKey); err != nil {
		return fmt.Errorf("mediaService.Delete: MinIO: %w", err)
	}

	// Удаляем метаданные из PostgreSQL
	return s.repo.Delete(ctx, id)
}
