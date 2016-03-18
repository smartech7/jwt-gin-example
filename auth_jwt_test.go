package JWT_MIDDLEWARE

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/appleboy/gin-jwt-server/tests"
	"github.com/stretchr/testify/assert"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)


var (
	key = []byte("secret key")
)

func makeTokenString(SigningAlgorithm string) string {

	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	token.Claims["id"] = "admin"
	token.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	tokenString, _ := token.SignedString(key)
	return tokenString
}

func HelloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text":         "Hello World.",
	})
}

func TestLoginHandler(t *testing.T) {

	// the middleware to test
	authMiddleware := &JWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		Authenticator: func(userId string, password string) bool {
			if userId == "admin" && password == "admin" {
				return true
			}
			return false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			return true
		},
	}

	// Missing usename or password
	data := `{"username":"admin"}`
	tests.RunSimplePost("/login", data,
		authMiddleware.LoginHandler,
		func(r *httptest.ResponseRecorder) {
			var rd map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&rd)

			if err != nil {
				log.Fatalf("JSON Decode fail: %v", err)
			}

			assert.Equal(t, rd["message"], "Missing usename or password")
			assert.Equal(t, r.Code, http.StatusBadRequest)
		})

	// incorrect password
	data = `{"username":"admin","password":"test"}`
	tests.RunSimplePost("/login", data,
		authMiddleware.LoginHandler,
		func(r *httptest.ResponseRecorder) {
			var rd map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&rd)

			if err != nil {
				log.Fatalf("JSON Decode fail: %v", err)
			}

			assert.Equal(t, rd["message"], "Incorrect Username / Password")
			assert.Equal(t, r.Code, http.StatusUnauthorized)
		})

	// login success
	data = `{"username":"admin","password":"admin"}`
	tests.RunSimplePost("/login", data,
		authMiddleware.LoginHandler,
		func(r *httptest.ResponseRecorder) {
			var rd map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&rd)

			if err != nil {
				log.Fatalf("JSON Decode fail: %v", err)
			}

			assert.Contains(t, "token", r.Body.String())
			assert.Contains(t, "expire", r.Body.String())
			assert.Equal(t, r.Code, http.StatusOK)
		})
}

func performRequest(r http.Handler, method, path string, token string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)

	if token != "" {
		req.Header.Set("Authorization", token)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func TestParseToken(t *testing.T) {
	// the middleware to test
	authMiddleware := &JWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		Authenticator: func(userId string, password string) bool {
			if userId == "admin" && password == "admin" {
				return true
			}

			return false
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/v1")
	v1.Use(authMiddleware.MiddlewareFunc())
	{
		v1.GET("/hello", HelloHandler)
	}

	w := performRequest(r, "GET", "/v1/hello", "")
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/hello", "Test 1234")
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/hello", "Bearer "+makeTokenString("HS384"))
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/hello", "Bearer "+makeTokenString("HS256"))
	assert.Equal(t, w.Code, http.StatusOK)
}

// func TestAuthJWT(t *testing.T) {
// 	// the middleware to test
// 	authMiddleware := &JWTMiddleware{
// 		Realm:      "test zone",
// 		Key:        key,
// 		Timeout:    time.Hour,
// 		Authenticator: func(userId string, password string) bool {
// 			if userId == "admin" && password == "admin" {
// 				return true
// 			}
// 			return false
// 		},
// 		Authorizator: func(userId string, c *gin.Context) bool {
// 			return true
// 		},
// 	}

// 	gin.SetMode(gin.TestMode)
// 	r := gin.New()

// 	v1 := r.Group("/v1")
// 	v1.Use(authMiddleware.MiddlewareFunc())
// 	{
// 		v1.GET("/refresh_token", authMiddleware.RefreshHandler)
// 	}
// }
