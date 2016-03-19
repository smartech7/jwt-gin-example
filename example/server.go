package main

import(
	"github.com/gin-gonic/gin"
	"github.com/appleboy/gin-jwt"
	"github.com/fvbock/endless"
	"os"
	"time"
)

func HelloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "Hello World.",
	})
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8000"
	}

	// the jwt middleware
	authMiddleware := &jwt.GinJWTMiddleware{
		Realm:   "test zone",
		Key:     []byte("secret key"),
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) bool {
			if (userId == "admin" && password == "admin") || (userId == "test" && password == "test") {
				return true
			}

			return false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			if userId == "admin" {
				return true
			}

			return false
		},
	}

	r.POST("/login", authMiddleware.LoginHandler)

	auth := r.Group("/auth")
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", HelloHandler)
		auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	}

	endless.ListenAndServe(":"+port, r)
}
