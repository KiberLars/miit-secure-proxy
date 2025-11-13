package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
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

func handlePublicProxy(c *gin.Context) {
	c.Request.Host = strings.Split(c.Request.Host, ":")[0]

	var upstream *UpstreamConfig
	for _, u := range config.Upstreams {
		if u.Host == c.Request.Host {
			upstream = &u
			break
		}
	}

	if upstream == nil {
		c.String(http.StatusNotFound, "Upstream не найден: %s", c.Request.Host)
		return
	}

	// Публичные маршруты - пропускаем без проверки доступа
	target, err := url.Parse(upstream.Destination)
	if err != nil {
		c.String(http.StatusInternalServerError, "Ошибка парсинга upstream: %v", err)
		return
	}

	// Обработка OPTIONS запросов для CORS (до проксирования)
	if c.Request.Method == "OPTIONS" {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Max-Age", "3600")
		c.Status(http.StatusNoContent)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Настраиваем директор для правильной передачи пути и заголовков
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Сохраняем оригинальный путь и параметры запроса
		req.URL.Path = c.Request.URL.Path
		req.URL.RawQuery = c.Request.URL.RawQuery
		// Устанавливаем заголовки для upstream
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", c.Request.Host)
		req.Header.Set("X-Real-IP", c.ClientIP())
		// Сохраняем оригинальный метод запроса
		req.Method = c.Request.Method
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func handleProxy(c *gin.Context) {
	c.Request.Host = strings.Split(c.Request.Host, ":")[0]

	var upstream *UpstreamConfig
	for _, u := range config.Upstreams {
		if u.Host == c.Request.Host {
			upstream = &u
			break
		}
	}

	if upstream == nil {
		c.String(http.StatusNotFound, "Upstream не найден: %s", c.Request.Host)
		return
	}

	username, exists := c.Get("username")
	if !exists {
		// Это не должно происходить, так как authMiddleware должен был сделать редирект
		// Но на всякий случай проверяем
		c.String(http.StatusUnauthorized, "Не авторизован")
		return
	}

	if !checkAccess(username.(string), c.Request.Host, c.Request.URL.Path, c) {
		return
	}

	target, _ := url.Parse(upstream.Destination)
	proxy := httputil.NewSingleHostReverseProxy(target)

	c.Request.URL.Host = target.Host
	c.Request.URL.Scheme = target.Scheme
	c.Request.Header.Set("X-Forwarded-Host", c.Request.Header.Get("Host"))
	c.Request.Host = target.Host

	proxy.ServeHTTP(c.Writer, c.Request)
}

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
		// Редирект на главную страницу ресторана при отсутствии прав
		redirectToMainPage(c)
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
