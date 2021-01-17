package main

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	authorizer := NewAuthorizer()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.GET("/authorize", func(c *gin.Context) {
		authorization := c.Request.Header.Get("Authorization")
		method := c.Request.Header.Get("X-Method")
		requestURI := c.Request.Header.Get("X-Request-URI")
		c.Header("application", "application/json; charset=utf-8")
		if len(authorization) <= len("Bearer") {
			c.Status(401)
			return
		}
		token := strings.Trim(authorization[len("Bearer"):], " ")
		ok, userInfo, err := authorizer.Authorize(token, method, requestURI)
		if err != nil {
			c.JSON(401, gin.H{"error": err.Error()})
			return
		}
		if !ok {
			c.Status(403)
			return
		}
		c.Header("X-Email", userInfo.Email)
		c.Header("X-User", userInfo.UserId)
		c.Header("X-Issuer", "google")
		c.Status(200)
	})
	r.Run(":5000") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
