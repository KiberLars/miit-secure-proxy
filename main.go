package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/valkey-io/valkey-go"
)

var config *Config
var valkeyClient valkey.Client

func main() {
	var err error
	config, err = ReadConfig()
	if err != nil {
		log.Fatal("Ошибка чтения конфигурации:", err)
	}

	valkeyClient, err = NewValkeyClient()
	if err != nil {
		log.Fatal("Ошибка подключения к Valkey:", err)
	}
	defer valkeyClient.Close()

	go func() {
		auth := gin.Default()
		auth.LoadHTMLGlob("templates/*")

		auth.GET("/", func(c *gin.Context) {
			redirectUrl := c.Query("redirectUrl")
			c.HTML(http.StatusOK, "login.html", gin.H{
				"redirectUrl": redirectUrl,
			})
		})

		auth.POST("/login", loginHandler)
		auth.RunTLS(":8443", "_.secure-proxy.lan.crt", "_.secure-proxy.lan.pem")
	}()

	proxy := gin.Default()
	proxy.Use(authMiddleware())

	proxy.Any("/*path", proxyHandler)
	proxy.RunTLS(":9443", "_.secure-proxy.lan.crt", "_.secure-proxy.lan.pem")
}

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
	redirectUrl := fmt.Sprintf("https://%s%s", c.Request.Host, c.Request.URL.String())
	authUrl := fmt.Sprintf("https://auth.secure-proxy.lan:8443/?redirectUrl=%s", url.QueryEscape(redirectUrl))
	c.Redirect(http.StatusFound, authUrl)
}

func loginHandler(c *gin.Context) {
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

func proxyHandler(c *gin.Context) {
	var upstream *UpstreamConfig
	c.Request.Host = strings.Split(c.Request.Host, ":")[0]
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

	target, _ := url.Parse(upstream.Destination)
	proxy := httputil.NewSingleHostReverseProxy(target)

	c.Request.URL.Host = target.Host
	c.Request.URL.Scheme = target.Scheme
	c.Request.Header.Set("X-Forwarded-Host", c.Request.Header.Get("Host"))
	c.Request.Host = target.Host

	proxy.ServeHTTP(c.Writer, c.Request)
}
