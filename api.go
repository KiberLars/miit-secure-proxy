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
}

type CreateUserRequest struct {
	Username     string   `json:"username" binding:"required"`
	AllowedPaths []string `json:"allowedPaths"`
}

type SessionResponse struct {
	Key      string `json:"key"`
	Username string `json:"username"`
	TTL      int64  `json:"ttl"`
}

func handleGetUsers(c *gin.Context) {
	users := make([]UserResponse, len(config.Users))
	for i, u := range config.Users {
		totpCode, _ := totp.GenerateCode(u.TOTPSecret, time.Now())
		users[i] = UserResponse{
			Username:     u.Username,
			TOTPSecret:   u.TOTPSecret,
			TOTPCode:     totpCode,
			AllowedPaths: u.AllowedPaths,
		}
	}
	c.JSON(http.StatusOK, users)
}

func handleCreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, u := range config.Users {
		if u.Username == req.Username {
			c.JSON(http.StatusConflict, gin.H{"error": "Пользователь уже существует"})
			return
		}
	}

	newUser := UserConfig{
		Username:     req.Username,
		TOTPSecret:   generateTOTPSecret(),
		AllowedPaths: req.AllowedPaths,
	}

	config.Users = append(config.Users, newUser)

	if err := SaveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения конфигурации: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, UserResponse{
		Username:     newUser.Username,
		TOTPSecret:   newUser.TOTPSecret,
		TOTPCode:     "",
		AllowedPaths: newUser.AllowedPaths,
	})
}

func handleUpdateUser(c *gin.Context) {
	username := c.Param("username")
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for i, u := range config.Users {
		if u.Username == username {
			config.Users[i].AllowedPaths = req.AllowedPaths
			if err := SaveConfig(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения конфигурации: " + err.Error()})
				return
			}
			totpCode, _ := totp.GenerateCode(config.Users[i].TOTPSecret, time.Now())
			c.JSON(http.StatusOK, UserResponse{
				Username:     config.Users[i].Username,
				TOTPSecret:   config.Users[i].TOTPSecret,
				TOTPCode:     totpCode,
				AllowedPaths: config.Users[i].AllowedPaths,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
}

func handleDeleteUser(c *gin.Context) {
	username := c.Param("username")

	for i, u := range config.Users {
		if u.Username == username {
			config.Users = append(config.Users[:i], config.Users[i+1:]...)
			if err := SaveConfig(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения конфигурации: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Пользователь удален"})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
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
