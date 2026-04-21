// Package service — RBAC сервис: проверка разрешений пользователя.
package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	pgRepo "github.com/yourusername/securestorage/internal/repository/postgres"
)

// RBACService — интерфейс проверки прав доступа.
type RBACService interface {
	// HasPermission проверяет, что пользователь с roleID имеет право resource:action.
	HasPermission(ctx context.Context, roleID uuid.UUID, resource, action string) (bool, error)
}

// rbacService — реализация RBACService.
type rbacService struct {
	userRepo pgRepo.UserRepository
	// cache: roleID → set of "resource:action"
	// В production следует использовать Redis или sync.Map с TTL.
	cache map[uuid.UUID]map[string]struct{}
}

// NewRBACService создаёт новый rbacService.
func NewRBACService(userRepo pgRepo.UserRepository) RBACService {
	return &rbacService{
		userRepo: userRepo,
		cache:    make(map[uuid.UUID]map[string]struct{}),
	}
}

// HasPermission проверяет наличие разрешения resource:action для роли roleID.
// Разрешения кешируются в памяти (per-process cache).
func (s *rbacService) HasPermission(
	ctx context.Context,
	roleID uuid.UUID,
	resource, action string,
) (bool, error) {
	permissions, err := s.getPermissions(ctx, roleID)
	if err != nil {
		return false, fmt.Errorf("rbac.HasPermission: %w", err)
	}

	key := resource + ":" + action
	_, ok := permissions[key]
	return ok, nil
}

// getPermissions возвращает множество разрешений роли (из кеша или из БД).
func (s *rbacService) getPermissions(ctx context.Context, roleID uuid.UUID) (map[string]struct{}, error) {
	if perms, ok := s.cache[roleID]; ok {
		return perms, nil
	}

	role, err := s.userRepo.GetRoleWithPermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}

	perms := make(map[string]struct{}, len(role.Permissions))
	for _, p := range role.Permissions {
		perms[p.Resource+":"+p.Action] = struct{}{}
	}

	s.cache[roleID] = perms
	return perms, nil
}
