// Package service реализует бизнес-логику работы с зашифрованными секретами.
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/yourusername/securestorage/internal/crypto"
	"github.com/yourusername/securestorage/internal/domain"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
)

// SecretService — интерфейс сервиса управления секретами.
type SecretService interface {
	Create(ctx context.Context, ownerID uuid.UUID, req domain.CreateSecretRequest) (*domain.SecretResponse, error)
	GetByID(ctx context.Context, requesterID uuid.UUID, requesterRoleName string, id uuid.UUID) (*domain.SecretResponse, error)
	List(ctx context.Context, requesterID uuid.UUID, requesterRoleName string, limit, offset int) ([]*domain.SecretListItem, int64, error)
	Update(ctx context.Context, requesterID uuid.UUID, id uuid.UUID, req domain.UpdateSecretRequest) (*domain.SecretResponse, error)
	Delete(ctx context.Context, requesterID uuid.UUID, requesterRoleName string, id uuid.UUID) error
}

// secretService — реализация SecretService.
type secretService struct {
	repo   pgRepo.SecretRepository
	cipher *crypto.Cipher
}

// NewSecretService создаёт новый secretService.
func NewSecretService(repo pgRepo.SecretRepository, cipher *crypto.Cipher) SecretService {
	return &secretService{repo: repo, cipher: cipher}
}

// Create шифрует payload и сохраняет новый секрет.
func (s *secretService) Create(
	ctx context.Context,
	ownerID uuid.UUID,
	req domain.CreateSecretRequest,
) (*domain.SecretResponse, error) {
	encData, iv, err := s.cipher.EncryptText([]byte(req.Payload))
	if err != nil {
		return nil, fmt.Errorf("secretService.Create: шифрование: %w", err)
	}

	secret := &domain.Secret{
		ID:            uuid.New(),
		OwnerID:       ownerID,
		Title:         req.Title,
		EncryptedData: encData,
		IV:            iv,
	}

	if err := s.repo.Create(ctx, secret); err != nil {
		return nil, fmt.Errorf("secretService.Create: сохранение: %w", err)
	}

	return &domain.SecretResponse{
		ID:        secret.ID,
		OwnerID:   secret.OwnerID,
		Title:     secret.Title,
		Payload:   req.Payload, // возвращаем оригинал создателю
		CreatedAt: secret.CreatedAt,
		UpdatedAt: secret.UpdatedAt,
	}, nil
}

// GetByID возвращает расшифрованный секрет.
// Обычный user может читать только свои секреты; admin/manager — любые.
func (s *secretService) GetByID(
	ctx context.Context,
	requesterID uuid.UUID,
	requesterRoleName string,
	id uuid.UUID,
) (*domain.SecretResponse, error) {
	secret, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgRepo.ErrSecretNotFound) {
			return nil, pgRepo.ErrSecretNotFound
		}
		return nil, fmt.Errorf("secretService.GetByID: %w", err)
	}

	// Проверка владельца для обычных пользователей
	if !isPrivileged(requesterRoleName) && secret.OwnerID != requesterID {
		return nil, pgRepo.ErrSecretForbidden
	}

	payload, err := s.cipher.DecryptText(secret.EncryptedData, secret.IV)
	if err != nil {
		return nil, fmt.Errorf("secretService.GetByID: дешифрование: %w", err)
	}

	return &domain.SecretResponse{
		ID:        secret.ID,
		OwnerID:   secret.OwnerID,
		Title:     secret.Title,
		Payload:   string(payload),
		CreatedAt: secret.CreatedAt,
		UpdatedAt: secret.UpdatedAt,
	}, nil
}

// List возвращает список секретов.
// Обычный user видит только свои; admin/manager — все.
func (s *secretService) List(
	ctx context.Context,
	requesterID uuid.UUID,
	requesterRoleName string,
	limit, offset int,
) ([]*domain.SecretListItem, int64, error) {
	var (
		secrets []*domain.Secret
		total   int64
		err     error
	)

	if isPrivileged(requesterRoleName) {
		secrets, total, err = s.repo.ListAll(ctx, limit, offset)
	} else {
		secrets, total, err = s.repo.ListByOwner(ctx, requesterID, limit, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("secretService.List: %w", err)
	}

	items := make([]*domain.SecretListItem, 0, len(secrets))
	for _, s := range secrets {
		items = append(items, &domain.SecretListItem{
			ID:        s.ID,
			OwnerID:   s.OwnerID,
			Title:     s.Title,
			CreatedAt: s.CreatedAt,
			UpdatedAt: s.UpdatedAt,
		})
	}

	return items, total, nil
}

// Update обновляет заголовок и/или payload секрета (только владелец).
func (s *secretService) Update(
	ctx context.Context,
	requesterID uuid.UUID,
	id uuid.UUID,
	req domain.UpdateSecretRequest,
) (*domain.SecretResponse, error) {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("secretService.Update: %w", err)
	}

	if existing.OwnerID != requesterID {
		return nil, pgRepo.ErrSecretForbidden
	}

	// Если title не менялся — оставляем старый
	if req.Title != "" {
		existing.Title = req.Title
	}

	// Если payload не менялся — перешифровывать не нужно
	var newPayload string
	if req.Payload != "" {
		encData, iv, err := s.cipher.EncryptText([]byte(req.Payload))
		if err != nil {
			return nil, fmt.Errorf("secretService.Update: шифрование: %w", err)
		}
		existing.EncryptedData = encData
		existing.IV = iv
		newPayload = req.Payload
	} else {
		// Возвращаем расшифрованный старый payload
		raw, err := s.cipher.DecryptText(existing.EncryptedData, existing.IV)
		if err != nil {
			return nil, fmt.Errorf("secretService.Update: дешифрование старого payload: %w", err)
		}
		newPayload = string(raw)
	}

	if err := s.repo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("secretService.Update: сохранение: %w", err)
	}

	return &domain.SecretResponse{
		ID:        existing.ID,
		OwnerID:   existing.OwnerID,
		Title:     existing.Title,
		Payload:   newPayload,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: existing.UpdatedAt,
	}, nil
}

// Delete удаляет секрет (только владелец или admin).
func (s *secretService) Delete(
	ctx context.Context,
	requesterID uuid.UUID,
	requesterRoleName string,
	id uuid.UUID,
) error {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("secretService.Delete: %w", err)
	}

	if !isPrivileged(requesterRoleName) && existing.OwnerID != requesterID {
		return pgRepo.ErrSecretForbidden
	}

	return s.repo.Delete(ctx, id)
}

// isPrivileged возвращает true если роль даёт право видеть все ресурсы.
func isPrivileged(roleName string) bool {
	return roleName == "admin" || roleName == "manager"
}
