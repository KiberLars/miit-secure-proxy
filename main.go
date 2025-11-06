package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
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

	go startAuthServer()
	startProxyServer()
}

func startAuthServer() {
	auth := gin.Default()
	auth.LoadHTMLGlob("templates/*")

	auth.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"redirectUrl": c.Query("redirectUrl"),
		})
	})

	auth.POST("/login", handleLogin)
	auth.GET("/admin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", gin.H{})
	})

	api := auth.Group("/api")
	{
		api.GET("/users", handleGetUsers)
		api.POST("/users", handleCreateUser)
		api.PUT("/users/:username", handleUpdateUser)
		api.DELETE("/users/:username", handleDeleteUser)
		api.GET("/sessions", handleGetSessions)
		api.DELETE("/sessions/:key", handleDeleteSession)
	}

	auth.RunTLS(":8443", "_.secure-proxy.lan.crt", "_.secure-proxy.lan.pem")
}

func startProxyServer() {
	proxy := gin.Default()
	proxy.Use(authMiddleware())
	proxy.Any("/*path", handleProxy)
	proxy.RunTLS(":9443", "_.secure-proxy.lan.crt", "_.secure-proxy.lan.pem")
}
