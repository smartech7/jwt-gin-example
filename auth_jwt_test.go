package jwt

import (
	"encoding/json"
	"github.com/appleboy/gin-jwt-server/tests"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	key = []byte("secret key")
)

func makeTokenString(SigningAlgorithm string, username string) string {

	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	token.Claims["id"] = username
	token.Claims["exp"] = time.Now().Add(time.Hour).Unix()
	tokenString, _ := token.SignedString(key)
	return tokenString
}

func HelloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "Hello World.",
	})
}

func TestLoginHandler(t *testing.T) {

	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		PayloadFunc: func(userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
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
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}

			return userId, false
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/v1")
	v1.Use(authMiddleware.MiddlewareFunc())
	{
		v1.GET("/auth_test", HelloHandler)
	}

	w := performRequest(r, "GET", "/v1/auth_test", "")
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/auth_test", "Test 1234")
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/auth_test", "Bearer "+makeTokenString("HS384", "admin"))
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/auth_test", "Bearer "+makeTokenString("HS256", "admin"))
	assert.Equal(t, w.Code, http.StatusOK)
}

func TestRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}

			return userId, false
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/v1")
	v1.Use(authMiddleware.MiddlewareFunc())
	{
		v1.GET("/refresh_token", authMiddleware.RefreshHandler)
	}

	// missing token
	w := performRequest(r, "GET", "/v1/refresh_token", "")
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	// wrong token
	w = performRequest(r, "GET", "/v1/refresh_token", "Test 1234")
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	w = performRequest(r, "GET", "/v1/refresh_token", "Bearer "+makeTokenString("HS256", "admin"))
	assert.Equal(t, w.Code, http.StatusOK)
}

func TestAuthorizator(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			if userId != "admin" {
				return false
			}

			return true
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/v1")
	v1.Use(authMiddleware.MiddlewareFunc())
	{
		v1.GET("/auth_test", HelloHandler)
	}

	w := performRequest(r, "GET", "/v1/auth_test", "Bearer "+makeTokenString("HS256", "test"))
	assert.Equal(t, w.Code, http.StatusForbidden)

	w = performRequest(r, "GET", "/v1/auth_test", "Bearer "+makeTokenString("HS256", "admin"))
	assert.Equal(t, w.Code, http.StatusOK)
}

func TestClaimsDuringAuthorization(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		PayloadFunc: func(userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			if userId == "test" && password == "test" {
				return "Administrator", true
			}

			return userId, false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			jwtClaims := ExtractClaims(c)

			// Check the actual claim, set in PayloadFunc
			return (jwtClaims["testkey"] == "testval" && (jwtClaims["id"] == "admin" || jwtClaims["id"] == "Administrator"))
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()

	v1 := r.Group("/v1")
	v1.Use(authMiddleware.MiddlewareFunc())
	{
		v1.GET("/auth_test", HelloHandler)
	}

	userToken := authMiddleware.TokenGenerator("admin")

	w := performRequest(r, "GET", "/v1/auth_test", "Bearer "+userToken)
	assert.Equal(t, w.Code, http.StatusOK)

	// login as test and set user id as Administrator
	data := `{"username":"admin","password":"admin"}`
	tests.RunSimplePost("/login", data,
		authMiddleware.LoginHandler,
		func(r *httptest.ResponseRecorder) {
			var rd map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&rd)

			if err != nil {
				log.Fatalf("JSON Decode fail: %v", err)
			}

			userToken = rd["token"].(string)
			assert.Equal(t, r.Code, http.StatusOK)
		})

	w = performRequest(r, "GET", "/v1/auth_test", "Bearer "+userToken)
	assert.Equal(t, w.Code, http.StatusOK)

	// login as test and set user id as Administrator
	data = `{"username":"test","password":"test"}`
	tests.RunSimplePost("/login", data,
		authMiddleware.LoginHandler,
		func(r *httptest.ResponseRecorder) {
			var rd map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&rd)

			if err != nil {
				log.Fatalf("JSON Decode fail: %v", err)
			}

			userToken = rd["token"].(string)
			assert.Equal(t, r.Code, http.StatusOK)
		})

	w = performRequest(r, "GET", "/v1/auth_test", "Bearer "+userToken)
	assert.Equal(t, w.Code, http.StatusOK)
}
