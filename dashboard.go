// Package main - обработчик dashboard страницы.
// Содержит функции для отображения главной страницы с доступными сервисами.
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type DashboardLink struct {
	Title string
	URL   string
}

func handleDashboard(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.String(http.StatusUnauthorized, "Не авторизован")
		return
	}

	usernameStr := username.(string)

	// Получаем права пользователя из Valkey
	permissions, err := GetUserPermissions(usernameStr)
	if err != nil {
		permissions = []string{}
	}

	currentHost := strings.Split(c.Request.Host, ":")[0]
	links := buildDashboardLinksFromPermissions(permissions, currentHost)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Username": usernameStr,
		"Links":    links,
	})
}

func buildDashboardLinksFromPermissions(permissions []string, currentHost string) []DashboardLink {
	var links []DashboardLink
	seen := make(map[string]bool)
	port := getProxyPort()

	for _, allowed := range permissions {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}

		var linkURL, linkTitle string

		if strings.Contains(allowed, "/") && !strings.HasPrefix(allowed, "/") {
			parts := strings.SplitN(allowed, "/", 2)
			host := parts[0]
			path := "/" + parts[1]
			linkURL = fmt.Sprintf("https://%s:%d%s", host, port, path)
			linkTitle = formatTitle(host, path)
		} else if strings.HasPrefix(allowed, "/") {
			linkURL = fmt.Sprintf("https://%s:%d%s", currentHost, port, allowed)
			linkTitle = formatTitle(currentHost, allowed)
		} else {
			linkURL = fmt.Sprintf("https://%s:%d/", allowed, port)
			linkTitle = formatTitle(allowed, "/")
		}

		if !seen[linkURL] {
			seen[linkURL] = true
			links = append(links, DashboardLink{
				Title: linkTitle,
				URL:   linkURL,
			})
		}
	}

	return links
}

func formatTitle(host, path string) string {
	if path == "/" {
		return host
	}
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		first := parts[0]
		if len(first) > 0 {
			return strings.ToUpper(first[:1]) + strings.ToLower(first[1:])
		}
		return first
	}
	return host
}

