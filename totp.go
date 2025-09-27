package main

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type TOTPResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	QRCodePNG string `json:"qr_code_png"`
}

func GenerateTOTPHandler(c *gin.Context) {
	issuer := c.DefaultQuery("issuer", "Secure Proxy")
	accountName := c.DefaultQuery("account_name", "user@secure-proxy.lan")
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации TOTP ключа"})
		return
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации QR изображения"})
		return
	}

	err = png.Encode(&buf, img)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при кодировании PNG"})
		return
	}

	qrCodeBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	response := TOTPResponse{
		Secret:    key.Secret(),
		QRCodeURL: key.URL(),
		QRCodePNG: qrCodeBase64,
	}

	c.JSON(http.StatusOK, response)
}

func ValidateTOTPHandler(c *gin.Context) {
	var request struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный запрос"})
		return
	}

	valid := totp.Validate(request.Code, request.Secret)
	c.JSON(http.StatusOK, gin.H{"valid": valid})
}
