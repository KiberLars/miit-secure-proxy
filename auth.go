package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

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

	var user *UserConfig
	for _, u := range config.Users {
		if u.Username == username {
			user = &u
			break
		}
	}

	if user == nil {
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
		redirectUrl = "https://site1.secure-proxy.lan"
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
