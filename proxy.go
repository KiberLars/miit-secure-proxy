// Package main - обработчики проксирования запросов.
// Содержит функции для публичного и защищенного проксирования запросов к upstream серверам.
package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// handlePublicProxy обрабатывает публичные запросы без проверки аутентификации
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
	configureProxyDirector(proxy, c)
	proxy.ServeHTTP(c.Writer, c.Request)
}

// handleProxy обрабатывает защищенные запросы с проверкой аутентификации и авторизации
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
		c.String(http.StatusUnauthorized, "Не авторизован")
		return
	}

	if !checkAccess(username.(string), c.Request.Host, c.Request.URL.Path, c) {
		return
	}

	target, err := url.Parse(upstream.Destination)
	if err != nil {
		c.String(http.StatusInternalServerError, "Ошибка парсинга upstream: %v", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	configureProxyDirector(proxy, c)
	proxy.ServeHTTP(c.Writer, c.Request)
}

// configureProxyDirector настраивает директор прокси для правильной передачи пути и заголовков
func configureProxyDirector(proxy *httputil.ReverseProxy, c *gin.Context) {
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = c.Request.URL.Path
		req.URL.RawQuery = c.Request.URL.RawQuery
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", c.Request.Host)
		req.Header.Set("X-Real-IP", c.ClientIP())
		req.Method = c.Request.Method
	}
}
