package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/valkey-io/valkey-go"
)

var config *Config
var valkeyClient valkey.Client

func main() {
	// Устанавливаем release режим для production
	gin.SetMode(gin.ReleaseMode)

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

	// Опциональная миграция пользователей из config.yaml в Valkey (только если указана переменная окружения)
	if os.Getenv("MIGRATE_FROM_CONFIG") == "true" {
		log.Println("Запуск миграции пользователей из config.yaml...")
		err = MigrateUsersFromConfig()
		if err != nil {
			log.Printf("Предупреждение: ошибка миграции пользователей: %v", err)
		} else {
			log.Println("Пользователи успешно мигрированы в Valkey")
		}
	}

	// Проверяем наличие сертификатов
	certFile := "certs/_.secure-proxy.lan.crt"
	keyFile := "certs/_.secure-proxy.lan.pem"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("Сертификат не найден: %s. Убедитесь, что файл находится в директории certs/", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("Ключ не найден: %s. Убедитесь, что файл находится в директории certs/", keyFile)
	}

	log.Println("Запуск auth сервера на порту 8443...")
	go func() {
		if err := startAuthServer(); err != nil {
			log.Printf("Ошибка запуска auth сервера: %v", err)
		}
	}()

	log.Println("Запуск proxy сервера на порту 9443...")
	startProxyServer()
}

func startAuthServer() error {
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

		// API для управления ролями
		api.GET("/roles", handleGetRoles)
		api.GET("/roles/:name", handleGetRole)
		api.POST("/roles", handleCreateRole)
		api.PUT("/roles/:name", handleUpdateRole)
		api.DELETE("/roles/:name", handleDeleteRole)
	}

	return auth.RunTLS(":8443", "certs/_.secure-proxy.lan.crt", "certs/_.secure-proxy.lan.pem")
}

func startProxyServer() {
	proxy := gin.Default()
	proxy.LoadHTMLGlob("templates/*")
	proxy.POST("/logout", handleLogout)

	// Публичные маршруты (без аутентификации) для пассажиров
	proxy.Any("/passenger", handlePublicProxy)
	proxy.Any("/passenger/*path", handlePublicProxy)
	// Публичные API для заказов (создание и просмотр заказов пассажирами)
	proxy.POST("/orders", handlePublicProxy)
	proxy.OPTIONS("/orders", handlePublicProxy)
	proxy.GET("/orders/:id", handlePublicProxy)
	proxy.OPTIONS("/orders/:id", handlePublicProxy)

	// Защищенные маршруты (требуют аутентификации)
	proxy.Use(authMiddleware())
	proxy.GET("/", handleDashboard)
	// Маршруты для официанта
	proxy.Any("/waiter", handleProxy)
	proxy.Any("/waiter/*path", handleProxy)
	proxy.NoRoute(handleProxy)
	port := getProxyPort()
	if err := proxy.RunTLS(fmt.Sprintf(":%d", port), "certs/_.secure-proxy.lan.crt", "certs/_.secure-proxy.lan.pem"); err != nil {
		log.Fatalf("Ошибка запуска proxy сервера: %v", err)
	}
}
