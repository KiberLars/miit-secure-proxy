package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type UserResponse struct {
	Username     string   `json:"username"`
	TOTPSecret   string   `json:"totpSecret"`
	TOTPCode     string   `json:"totpCode"`
	AllowedPaths []string `json:"allowedPaths"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
}

type CreateUserRequest struct {
	Username     string   `json:"username" binding:"required"`
	AllowedPaths []string `json:"allowedPaths"`
	Roles        []string `json:"roles"`
}

type RoleResponse struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type CreateRoleRequest struct {
	Name        string   `json:"name" binding:"required"`
	Permissions []string `json:"permissions"`
}

type SessionResponse struct {
	Key      string `json:"key"`
	Username string `json:"username"`
	TTL      int64  `json:"ttl"`
}

func handleGetUsers(c *gin.Context) {
	// Получаем пользователей из Valkey
	valkeyUsers, err := GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользователей: " + err.Error()})
		return
	}

	users := make([]UserResponse, 0, len(valkeyUsers))
	for username, user := range valkeyUsers {
		totpCode, _ := totp.GenerateCode(user.TOTPSecret, time.Now())
		permissions, _ := GetUserPermissions(username)

		users = append(users, UserResponse{
			Username:     username,
			TOTPSecret:   user.TOTPSecret,
			TOTPCode:     totpCode,
			AllowedPaths: permissions, // Для обратной совместимости
			Roles:        user.Roles,
			Permissions:  permissions,
		})
	}
	c.JSON(http.StatusOK, users)
}

func handleCreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверяем, существует ли пользователь в Valkey
	_, err := GetUser(req.Username)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Пользователь уже существует"})
		return
	}

	totpSecret := generateTOTPSecret()
	roles := req.Roles

	// Сохраняем пользователя в Valkey
	err = SaveUser(req.Username, totpSecret, roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения пользователя: " + err.Error()})
		return
	}

	permissions, _ := GetUserPermissions(req.Username)
	c.JSON(http.StatusOK, UserResponse{
		Username:     req.Username,
		TOTPSecret:   totpSecret,
		TOTPCode:     "",
		AllowedPaths: permissions,
		Roles:        roles,
		Permissions:  permissions,
	})
}

func handleUpdateUser(c *gin.Context) {
	username := c.Param("username")
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Получаем пользователя из Valkey
	user, err := GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Обновляем роли пользователя
	roles := req.Roles

	// Сохраняем обновленного пользователя
	err = SaveUser(username, user.TOTPSecret, roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления пользователя: " + err.Error()})
		return
	}

	totpCode, _ := totp.GenerateCode(user.TOTPSecret, time.Now())
	permissions, _ := GetUserPermissions(username)
	c.JSON(http.StatusOK, UserResponse{
		Username:     username,
		TOTPSecret:   user.TOTPSecret,
		TOTPCode:     totpCode,
		AllowedPaths: permissions,
		Roles:        roles,
		Permissions:  permissions,
	})
}

func handleDeleteUser(c *gin.Context) {
	username := c.Param("username")

	// Проверяем, существует ли пользователь
	_, err := GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Удаляем из Valkey
	err = DeleteUser(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления пользователя: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Пользователь удален"})
}

func handleGetSessions(c *gin.Context) {
	sessions, err := getAllSessions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

func handleDeleteSession(c *gin.Context) {
	sessionKey := c.Param("key")
	ctx := context.Background()

	err := valkeyClient.Do(ctx, valkeyClient.B().Del().Key(sessionKey).Build()).Error()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session deleted"})
}

func getAllSessions() ([]SessionResponse, error) {
	ctx := context.Background()
	var sessions []SessionResponse

	sessionKeyPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)

	keysResult := valkeyClient.Do(ctx, valkeyClient.B().Keys().Pattern("*").Build())
	keys, err := keysResult.AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения ключей: %v", err)
	}

	for _, key := range keys {
		if sessionKeyPattern.MatchString(key) {
			username, err := valkeyClient.Do(ctx, valkeyClient.B().Get().Key(key).Build()).ToString()
			if err != nil {
				continue
			}

			ttlResult := valkeyClient.Do(ctx, valkeyClient.B().Ttl().Key(key).Build())
			ttl, err := ttlResult.AsInt64()
			if err != nil {
				ttl = -1
			}

			sessions = append(sessions, SessionResponse{
				Key:      key,
				Username: username,
				TTL:      ttl,
			})
		}
	}

	return sessions, nil
}

// Обработчики для ролей
func handleGetRoles(c *gin.Context) {
	roles, err := GetAllRoles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	roleList := make([]RoleResponse, 0, len(roles))
	for name, permissions := range roles {
		roleList = append(roleList, RoleResponse{
			Name:        name,
			Permissions: permissions,
		})
	}

	c.JSON(http.StatusOK, roleList)
}

func handleCreateRole(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверяем, существует ли роль
	_, err := GetRolePermissions(req.Name)
	if err == nil {
		// Роль уже существует, проверяем через GetAllRoles
		roles, _ := GetAllRoles()
		if _, exists := roles[req.Name]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "Роль уже существует"})
			return
		}
	}

	err = SetRolePermissions(req.Name, req.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания роли: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, RoleResponse{
		Name:        req.Name,
		Permissions: req.Permissions,
	})
}

func handleUpdateRole(c *gin.Context) {
	roleName := c.Param("name")
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверяем, существует ли роль
	_, err := GetRolePermissions(roleName)
	if err != nil {
		// Роль не существует
		roles, _ := GetAllRoles()
		if _, exists := roles[roleName]; !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Роль не найдена"})
			return
		}
	}

	err = SetRolePermissions(roleName, req.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления роли: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, RoleResponse{
		Name:        roleName,
		Permissions: req.Permissions,
	})
}

func handleDeleteRole(c *gin.Context) {
	roleName := c.Param("name")

	err := DeleteRole(roleName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления роли: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Роль удалена"})
}

func handleGetRole(c *gin.Context) {
	roleName := c.Param("name")

	permissions, err := GetRolePermissions(roleName)
	if err != nil {
		// Проверяем через GetAllRoles
		roles, _ := GetAllRoles()
		if _, exists := roles[roleName]; !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Роль не найдена"})
			return
		}
		permissions = roles[roleName]
	}

	c.JSON(http.StatusOK, RoleResponse{
		Name:        roleName,
		Permissions: permissions,
	})
}
