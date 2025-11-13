package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Структура для хранения пользователя в Valkey
type ValkeyUser struct {
	TOTPSecret string   `json:"totpSecret"`
	Roles      []string `json:"roles"`
}

// Ключи для хранения в Valkey
const (
	userKeyPrefix         = "user:"
	rolePermissionsPrefix = "role:permissions:"
	userRolesPrefix       = "user:roles:"
)

// getUserKey возвращает ключ для хранения данных пользователя
func getUserKey(username string) string {
	return userKeyPrefix + username
}

// getRolePermissionsKey возвращает ключ для хранения прав роли
func getRolePermissionsKey(roleName string) string {
	return rolePermissionsPrefix + roleName
}

// getUserRolesKey возвращает ключ для хранения ролей пользователя
func getUserRolesKey(username string) string {
	return userRolesPrefix + username
}

// SaveUser сохраняет пользователя в Valkey
func SaveUser(username string, totpSecret string, roles []string) error {
	ctx := context.Background()
	userKey := getUserKey(username)

	user := ValkeyUser{
		TOTPSecret: totpSecret,
		Roles:      roles,
	}

	userJSON, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("ошибка сериализации пользователя: %v", err)
	}

	// Сохраняем данные пользователя
	err = valkeyClient.Do(ctx, valkeyClient.B().Set().Key(userKey).Value(string(userJSON)).Build()).Error()
	if err != nil {
		return fmt.Errorf("ошибка сохранения пользователя: %v", err)
	}

	// Сохраняем роли пользователя в отдельный Set для быстрого доступа
	userRolesKey := getUserRolesKey(username)
	if len(roles) > 0 {
		// Удаляем старые роли
		valkeyClient.Do(ctx, valkeyClient.B().Del().Key(userRolesKey).Build())
		// Добавляем новые роли
		for _, role := range roles {
			valkeyClient.Do(ctx, valkeyClient.B().Sadd().Key(userRolesKey).Member(role).Build())
		}
	} else {
		// Если ролей нет, удаляем ключ
		valkeyClient.Do(ctx, valkeyClient.B().Del().Key(userRolesKey).Build())
	}

	return nil
}

// GetUser получает пользователя из Valkey
func GetUser(username string) (*ValkeyUser, error) {
	ctx := context.Background()
	userKey := getUserKey(username)

	result := valkeyClient.Do(ctx, valkeyClient.B().Get().Key(userKey).Build())
	userJSON, err := result.ToString()
	if err != nil {
		return nil, fmt.Errorf("пользователь не найден: %v", err)
	}

	var user ValkeyUser
	err = json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		return nil, fmt.Errorf("ошибка десериализации пользователя: %v", err)
	}

	return &user, nil
}

// DeleteUser удаляет пользователя из Valkey
func DeleteUser(username string) error {
	ctx := context.Background()
	userKey := getUserKey(username)
	userRolesKey := getUserRolesKey(username)

	// Удаляем данные пользователя и его роли
	valkeyClient.Do(ctx, valkeyClient.B().Del().Key(userKey).Build())
	valkeyClient.Do(ctx, valkeyClient.B().Del().Key(userRolesKey).Build())

	return nil
}

// GetAllUsers получает всех пользователей из Valkey
func GetAllUsers() (map[string]*ValkeyUser, error) {
	ctx := context.Background()
	users := make(map[string]*ValkeyUser)

	// Получаем все ключи пользователей
	keysResult := valkeyClient.Do(ctx, valkeyClient.B().Keys().Pattern(userKeyPrefix+"*").Build())
	keys, err := keysResult.AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения ключей: %v", err)
	}

	for _, key := range keys {
		username := strings.TrimPrefix(key, userKeyPrefix)
		user, err := GetUser(username)
		if err != nil {
			continue
		}
		users[username] = user
	}

	return users, nil
}

// SetRolePermissions устанавливает права для роли
func SetRolePermissions(roleName string, permissions []string) error {
	ctx := context.Background()
	roleKey := getRolePermissionsKey(roleName)

	// Удаляем старые права
	valkeyClient.Do(ctx, valkeyClient.B().Del().Key(roleKey).Build())

	// Добавляем новые права
	if len(permissions) > 0 {
		for _, perm := range permissions {
			valkeyClient.Do(ctx, valkeyClient.B().Sadd().Key(roleKey).Member(perm).Build())
		}
	}

	return nil
}

// GetRolePermissions получает права роли
func GetRolePermissions(roleName string) ([]string, error) {
	ctx := context.Background()
	roleKey := getRolePermissionsKey(roleName)

	result := valkeyClient.Do(ctx, valkeyClient.B().Smembers().Key(roleKey).Build())
	permissions, err := result.AsStrSlice()
	if err != nil {
		return []string{}, nil // Роль не существует или нет прав
	}

	return permissions, nil
}

// DeleteRole удаляет роль
func DeleteRole(roleName string) error {
	ctx := context.Background()
	roleKey := getRolePermissionsKey(roleName)

	valkeyClient.Do(ctx, valkeyClient.B().Del().Key(roleKey).Build())

	return nil
}

// GetAllRoles получает все роли
func GetAllRoles() (map[string][]string, error) {
	ctx := context.Background()
	roles := make(map[string][]string)

	// Получаем все ключи ролей
	keysResult := valkeyClient.Do(ctx, valkeyClient.B().Keys().Pattern(rolePermissionsPrefix+"*").Build())
	keys, err := keysResult.AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения ключей: %v", err)
	}

	for _, key := range keys {
		roleName := strings.TrimPrefix(key, rolePermissionsPrefix)
		permissions, err := GetRolePermissions(roleName)
		if err != nil {
			continue
		}
		roles[roleName] = permissions
	}

	return roles, nil
}

// GetUserPermissions получает все права пользователя (объединение прав всех его ролей)
func GetUserPermissions(username string) ([]string, error) {
	ctx := context.Background()
	userRolesKey := getUserRolesKey(username)

	// Получаем роли пользователя
	rolesResult := valkeyClient.Do(ctx, valkeyClient.B().Smembers().Key(userRolesKey).Build())
	roles, err := rolesResult.AsStrSlice()
	if err != nil {
		return []string{}, nil // У пользователя нет ролей
	}

	// Собираем все права из всех ролей
	permissionsMap := make(map[string]bool)
	for _, role := range roles {
		rolePerms, err := GetRolePermissions(role)
		if err != nil {
			continue
		}
		for _, perm := range rolePerms {
			permissionsMap[perm] = true
		}
	}

	// Преобразуем map в slice
	permissions := make([]string, 0, len(permissionsMap))
	for perm := range permissionsMap {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// CheckUserPermission проверяет, есть ли у пользователя определенное право
func CheckUserPermission(username string, permission string) (bool, error) {
	permissions, err := GetUserPermissions(username)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm == permission {
			return true, nil
		}
		// Поддержка wildcard прав (например, "rest.secure-proxy.lan/*" для "rest.secure-proxy.lan/warehouse")
		if strings.HasSuffix(perm, "/*") {
			prefix := strings.TrimSuffix(perm, "/*")
			if strings.HasPrefix(permission, prefix+"/") {
				return true, nil
			}
		}
	}

	return false, nil
}

// MigrateUsersFromConfig мигрирует пользователей из config.yaml в Valkey
// Миграция выполняется только если пользователь еще не существует в Valkey
// Эта функция используется только при явном указании переменной окружения MIGRATE_FROM_CONFIG=true
func MigrateUsersFromConfig() error {
	if config == nil || len(config.Users) == 0 {
		return nil
	}

	for _, user := range config.Users {
		// Проверяем, существует ли пользователь в Valkey
		_, err := GetUser(user.Username)
		if err == nil {
			// Пользователь уже существует, пропускаем
			continue
		}

		// Преобразуем AllowedPaths в права (permissions)
		permissions := user.AllowedPaths

		// Сохраняем пользователя в Valkey
		err = SaveUser(user.Username, user.TOTPSecret, []string{})
		if err != nil {
			return fmt.Errorf("ошибка миграции пользователя %s: %v", user.Username, err)
		}

		// Если у пользователя есть права, создаем роль с именем пользователя
		if len(permissions) > 0 {
			// Создаем роль с именем пользователя
			err = SetRolePermissions(user.Username, permissions)
			if err != nil {
				return fmt.Errorf("ошибка создания роли для пользователя %s: %v", user.Username, err)
			}
			// Привязываем пользователя к его роли
			err = SaveUser(user.Username, user.TOTPSecret, []string{user.Username})
			if err != nil {
				return fmt.Errorf("ошибка привязки роли пользователю %s: %v", user.Username, err)
			}
		}
	}

	return nil
}
