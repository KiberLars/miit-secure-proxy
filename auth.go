package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionKey, err := c.Cookie(config.Sessions.CookieName)
		if err != nil {
			redirectToAuth(c)
			return
		}

		ctx := context.Background()
		username, err := valkeyClient.Do(ctx, valkeyClient.B().Get().Key(sessionKey).Build()).ToString()
		if err != nil {
			redirectToAuth(c)
			return
		}

		valkeyClient.Do(ctx, valkeyClient.B().Expire().Key(sessionKey).Seconds(int64(config.Sessions.TTLSeconds)).Build())
		c.Set("username", username)
		c.Next()
	}
}

func redirectToAuth(c *gin.Context) {
	// Формируем полный URL запроса с учетом схемы и порта
	requestURL := c.Request.URL
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}

	host := c.Request.Host
	if host == "" {
		host = c.Request.Header.Get("Host")
	}

	// Формируем полный URL для редиректа
	redirectUrl := fmt.Sprintf("%s://%s%s", scheme, host, requestURL.String())
	authUrl := fmt.Sprintf("https://auth.secure-proxy.lan:8443/?redirectUrl=%s", url.QueryEscape(redirectUrl))
	c.Redirect(http.StatusFound, authUrl)
	c.Abort()
}

func handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	totpCode := c.PostForm("totp")
	redirectUrl := c.PostForm("redirectUrl")

	// Получаем пользователя из Valkey
	user, err := GetUser(username)
	if err != nil {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"error":       "нет имени",
			"redirectUrl": redirectUrl,
		})
		return
	}

	if !totp.Validate(totpCode, user.TOTPSecret) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"error":       "неправильный ОТП",
			"redirectUrl": redirectUrl,
		})
		return
	}

	sessionKey := generateSessionKey()
	ctx := context.Background()
	valkeyClient.Do(ctx, valkeyClient.B().Set().Key(sessionKey).Value(username).ExSeconds(int64(config.Sessions.TTLSeconds)).Build())

	c.SetCookie(
		config.Sessions.CookieName,
		sessionKey,
		config.Sessions.TTLSeconds,
		"/",
		config.Sessions.CookieDomain,
		true,
		true,
	)

	if redirectUrl == "" {
		redirectUrl = resolveDefaultRedirectFromValkey(user, username)
	}
	c.Redirect(http.StatusFound, redirectUrl)
}

func generateSessionKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateTOTPSecret() string {
	bytes := make([]byte, 20)
	rand.Read(bytes)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)
}

func resolveDefaultRedirectFromValkey(user *ValkeyUser, username string) string {
	fallbackHost := defaultUpstreamHost()
	defaultHost := getDefaultProxyHost()
	port := getProxyPort()

	// Получаем права пользователя
	permissions, err := GetUserPermissions(username)
	if err != nil || len(permissions) == 0 {
		if fallbackHost == "" {
			return fmt.Sprintf("https://%s:%d/", defaultHost, port)
		}
		return fmt.Sprintf("https://%s:%d/", fallbackHost, port)
	}

	candidate := strings.TrimSpace(permissions[0])
	if candidate == "" {
		if fallbackHost == "" {
			return fmt.Sprintf("https://%s:%d/", defaultHost, port)
		}
		return fmt.Sprintf("https://%s:%d/", fallbackHost, port)
	}

	if strings.Contains(candidate, "://") {
		return candidate
	}

	if strings.HasPrefix(candidate, "/") {
		if fallbackHost == "" {
			return fmt.Sprintf("https://%s:%d%s", defaultHost, port, candidate)
		}
		return fmt.Sprintf("https://%s:%d%s", fallbackHost, port, candidate)
	}

	parts := strings.SplitN(candidate, "/", 2)
	host := strings.TrimSpace(parts[0])
	path := ""
	if len(parts) > 1 {
		path = "/" + parts[1]
	}

	if host == "" {
		host = fallbackHost
	}

	if host == "" {
		return fmt.Sprintf("https://%s:%d/%s", defaultHost, port, strings.TrimPrefix(path, "/"))
	}

	return fmt.Sprintf("https://%s:%d%s", host, port, path)
}

func defaultUpstreamHost() string {
	if config == nil || len(config.Upstreams) == 0 {
		return ""
	}
	return config.Upstreams[0].Host
}

func getDefaultProxyHost() string {
	if config != nil && config.Proxy.DefaultHost != "" {
		return config.Proxy.DefaultHost
	}
	if config != nil && len(config.Upstreams) > 0 {
		return config.Upstreams[0].Host
	}
	return "rest.secure-proxy.lan"
}

func getProxyPort() int {
	if config != nil && config.Proxy.Port > 0 {
		return config.Proxy.Port
	}
	return 9443
}

func handleLogout(c *gin.Context) {
	sessionKey, err := c.Cookie(config.Sessions.CookieName)
	if err == nil && sessionKey != "" {
		ctx := context.Background()
		valkeyClient.Do(ctx, valkeyClient.B().Del().Key(sessionKey).Build())
	}

	c.SetCookie(
		config.Sessions.CookieName,
		"",
		-1,
		"/",
		config.Sessions.CookieDomain,
		true,
		true,
	)

	c.Redirect(http.StatusFound, "https://auth.secure-proxy.lan:8443/")
}

func getDashboardURL() string {
	host := getDefaultProxyHost()
	port := getProxyPort()
	return fmt.Sprintf("https://%s:%d/", host, port)
}
