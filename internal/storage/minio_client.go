// Package storage инициализирует и предоставляет клиент MinIO.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog/log"
	"github.com/yourusername/securestorage/internal/config"
)

// MinIOClient — обёртка над minio.Client с дополнительными методами.
type MinIOClient struct {
	client     *minio.Client
	BucketName string
}

// NewMinIOClient создаёт подключение к MinIO и инициализирует bucket.
func NewMinIOClient(ctx context.Context, cfg config.MinIOConfig) (*MinIOClient, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio: создание клиента: %w", err)
	}

	mc := &MinIOClient{
		client:     client,
		BucketName: cfg.Bucket,
	}

	// Создаём bucket если не существует
	if err := mc.ensureBucket(ctx); err != nil {
		return nil, err
	}

	log.Info().
		Str("endpoint", cfg.Endpoint).
		Str("bucket", cfg.Bucket).
		Msg("MinIO: подключение установлено")

	return mc, nil
}

// ensureBucket создаёт bucket если его нет.
func (m *MinIOClient) ensureBucket(ctx context.Context) error {
	exists, err := m.client.BucketExists(ctx, m.BucketName)
	if err != nil {
		return fmt.Errorf("minio: проверка bucket: %w", err)
	}

	if !exists {
		if err := m.client.MakeBucket(ctx, m.BucketName, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("minio: создание bucket %q: %w", m.BucketName, err)
		}
		log.Info().Str("bucket", m.BucketName).Msg("MinIO: bucket создан")

		// Применяем политику закрытого доступа (private)
		if err := m.setPrivatePolicy(ctx); err != nil {
			log.Warn().Err(err).Msg("MinIO: не удалось установить политику доступа")
		}
	}

	return nil
}

// setPrivatePolicy запрещает публичный доступ к bucket.
func (m *MinIOClient) setPrivatePolicy(ctx context.Context) error {
	policy := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": ["s3:GetObject"],
			"Resource": ["arn:aws:s3:::%s/*"]
		}]
	}`, m.BucketName)

	return m.client.SetBucketPolicy(ctx, m.BucketName, policy)
}

// PutObject загружает объект в MinIO.
func (m *MinIOClient) PutObject(
	ctx context.Context,
	objectKey string,
	data []byte,
	contentType string,
) (minio.UploadInfo, error) {
	reader := bytes.NewReader(data)
	info, err := m.client.PutObject(
		ctx,
		m.BucketName,
		objectKey,
		reader,
		int64(len(data)),
		minio.PutObjectOptions{
			ContentType: contentType,
		},
	)
	if err != nil {
		return minio.UploadInfo{}, fmt.Errorf("minio: загрузка объекта %q: %w", objectKey, err)
	}
	return info, nil
}

// GetObject скачивает объект из MinIO и возвращает его содержимое.
func (m *MinIOClient) GetObject(ctx context.Context, objectKey string) ([]byte, error) {
	obj, err := m.client.GetObject(ctx, m.BucketName, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio: получение объекта %q: %w", objectKey, err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("minio: чтение объекта %q: %w", objectKey, err)
	}
	return data, nil
}

// DeleteObject удаляет объект из MinIO.
func (m *MinIOClient) DeleteObject(ctx context.Context, objectKey string) error {
	err := m.client.RemoveObject(ctx, m.BucketName, objectKey, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("minio: удаление объекта %q: %w", objectKey, err)
	}
	return nil
}
