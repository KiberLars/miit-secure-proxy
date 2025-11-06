package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

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
	var user *UserConfig
	for _, u := range config.Users {
		if u.Username == username {
			user = &u
			break
		}
	}

	if user == nil || len(user.AllowedPaths) == 0 {
		return true
	}

	requestHost = strings.Split(requestHost, ":")[0]

	if strings.HasPrefix(requestPath, "/static/") {
		return checkStaticAccess(user, requestHost, requestPath, c)
	}

	return checkPathAccess(user, requestHost, requestPath)
}

func checkStaticAccess(user *UserConfig, requestHost, requestPath string, c *gin.Context) bool {
	referer := c.Request.Header.Get("Referer")
	if referer != "" {
		refererURL, err := url.Parse(referer)
		if err == nil {
			refererHost := strings.Split(refererURL.Host, ":")[0]
			refererPath := refererURL.Path
			if checkPathAccess(user, refererHost, refererPath) {
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

	c.String(http.StatusForbidden, "Доступ запрещен. Разрешенные пути: %s", strings.Join(user.AllowedPaths, ", "))
	return false
}

func checkPathAccess(user *UserConfig, requestHost, requestPath string) bool {
	for _, allowed := range user.AllowedPaths {
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
