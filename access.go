// Package main - проверка доступа пользователей к ресурсам.
// Содержит функции для проверки прав доступа на основе разрешений пользователя.
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func checkAccess(username, requestHost, requestPath string, c *gin.Context) bool {
	requestHost = strings.Split(requestHost, ":")[0]

	// Получаем права пользователя из Valkey
	permissions, err := GetUserPermissions(username)
	if err != nil {
		// Если пользователь не найден или ошибка, разрешаем доступ (можно изменить на запрет)
		return true
	}

	// Если прав нет, разрешаем доступ
	if len(permissions) == 0 {
		return true
	}

	if strings.HasPrefix(requestPath, "/static/") {
		return checkStaticAccessFromPermissions(permissions, requestHost, requestPath, c)
	}

	hasAccess := checkPathAccessFromPermissions(permissions, requestHost, requestPath)
	if !hasAccess {
		// Проверяем, является ли запрос API запросом
		acceptHeader := c.GetHeader("Accept")
		contentType := c.GetHeader("Content-Type")
		isAPIRequest := strings.Contains(acceptHeader, "application/json") ||
			strings.Contains(contentType, "application/json") ||
			strings.HasPrefix(requestPath, "/waiter/") ||
			strings.HasPrefix(requestPath, "/api/")

		if isAPIRequest {
			// Для API запросов возвращаем JSON ошибку
			c.JSON(http.StatusForbidden, gin.H{
				"detail": "Доступ запрещен. Недостаточно прав для доступа к этому ресурсу.",
			})
		} else {
			// Для обычных запросов делаем редирект
			redirectToMainPage(c)
		}
		return false
	}

	return true
}

func checkPathAccessFromPermissions(permissions []string, requestHost, requestPath string) bool {
	for _, allowed := range permissions {
		if strings.Contains(allowed, "/") {
			parts := strings.SplitN(allowed, "/", 2)
			allowedHost := parts[0]
			allowedPath := "/" + parts[1]
			if allowedHost == requestHost && strings.HasPrefix(requestPath, allowedPath) {
				return true
			}
		} else if strings.HasPrefix(allowed, "/") {
			if strings.HasPrefix(requestPath, allowed) {
				return true
			}
		} else {
			if allowed == requestHost {
				return true
			}
		}
	}
	return false
}

func checkStaticAccessFromPermissions(permissions []string, requestHost, requestPath string, c *gin.Context) bool {
	referer := c.Request.Header.Get("Referer")
	if referer != "" {
		refererURL, err := url.Parse(referer)
		if err == nil {
			refererHost := strings.Split(refererURL.Host, ":")[0]
			refererPath := refererURL.Path
			if checkPathAccessFromPermissions(permissions, refererHost, refererPath) {
				return true
			}
		}
	}

	allowedExts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range allowedExts {
		if strings.HasSuffix(requestPath, ext) {
			return true
		}
	}

	// Редирект на главную страницу ресторана при отсутствии прав
	redirectToMainPage(c)
	return false
}

// redirectToMainPage перенаправляет пользователя на главную страницу ресторана
func redirectToMainPage(c *gin.Context) {
	defaultHost := getDefaultProxyHost()
	port := getProxyPort()
	mainURL := fmt.Sprintf("https://%s:%d/", defaultHost, port)
	c.Redirect(http.StatusFound, mainURL)
}

