package main

import (
	"errors"
	"net/http"
	"os"

	"github.com/damascopaul/authenticate-go/middlewares"
	"github.com/damascopaul/authenticate-go/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	log.SetFormatter(&logrus.JSONFormatter{})
	r := gin.Default()
	r.Use(middlewares.InjectRequestIDMiddleware)
	r.POST("/authenticate", processAuthenticate)
	r.Run() // listen and serve on 0.0.0.0:8080
}

func processAuthenticate(c *gin.Context) {
	reqID, _ := c.Get("RequestID")
	log.WithFields(logrus.Fields{"request": reqID}).Info("Request received")
	c.Header("Content-Type", "application/json")

	// Parse the request body
	var req types.RequestBody
	if err := c.BindJSON(&req); err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"request": reqID,
		}).Warn("Failed to parse request body")
		c.AbortWithStatusJSON(
			http.StatusBadRequest, types.ResponseError{Message: "This only supports JSON"})
		return
	}
	log.WithFields(logrus.Fields{"request": reqID}).Info("Parsed the request body")

	// Retrieve the token secret from environment variables
	secret := os.Getenv("TOKEN_SECRET")
	if secret == "" {
		log.WithFields(logrus.Fields{
			"error":   "The token secret is not configured",
			"request": reqID,
		}).Fatal("App configuration error")
		c.AbortWithStatusJSON(
			http.StatusInternalServerError, types.ResponseError{Message: "Server error encountered"})
		return
	}

	// Parse the token
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		// Check the token alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.WithFields(logrus.Fields{
				"error":   "The token is not signed correctly",
				"request": reqID,
			}).Warn("Token parse error")
			c.AbortWithStatusJSON(
				http.StatusForbidden, types.ResponseError{Message: "Token is not valid"})
			return nil, errors.New("token is signed incorrectly")
		}
		return []byte(secret), nil
	})
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"request": reqID,
		}).Warn("Token parse error")
		c.AbortWithStatusJSON(
			http.StatusForbidden, types.ResponseError{Message: "Token is not valid"})
		return
	}
	log.WithFields(logrus.Fields{"request": reqID}).Info("Parsed the token")

	// Check the token claims
	if _, ok := token.Claims.(jwt.MapClaims); !ok {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"request": reqID,
		}).Warn("Token claim error")
		c.AbortWithStatusJSON(
			http.StatusForbidden, types.ResponseError{Message: "Token is not valid"})
	}

	c.JSON(http.StatusOK, gin.H{})
	log.WithFields(logrus.Fields{"request": reqID}).Info("Request processed")
}
