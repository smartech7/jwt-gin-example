package jwt

import (
	"github.com/appleboy/gofight"
	"github.com/buger/jsonparser"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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

func TestMissingRealm(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "Realm is required", err.Error())
}

func TestMissingAuthenticator(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "Authenticator is required", err.Error())
}

func TestMissingKey(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "Key is required", err.Error())
}

func TestMissingTimeOut(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	authMiddleware.MiddlewareInit()

	assert.Equal(t, time.Hour, authMiddleware.Timeout)
}

func helloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "Hello World.",
	})
}

func ginHandler(auth *GinJWTMiddleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.POST("/login", auth.LoginHandler)

	group := r.Group("/auth")
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/hello", helloHandler)
		group.GET("/refresh_token", auth.RefreshHandler)
	}

	return r
}

func TestLoginHandler(t *testing.T) {

	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm: "test zone",
		Key:   key,
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

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			message, _ := jsonparser.GetString(data, "message")

			assert.Equal(t, "Missing usename or password", message)
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			message, _ := jsonparser.GetString(data, "message")

			assert.Equal(t, "Incorrect Username / Password", message)
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
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

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
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

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
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

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "test"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusForbidden, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
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

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	userToken := authMiddleware.TokenGenerator("admin")

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			token, _ := jsonparser.GetString(data, "token")
			userToken = token
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "test",
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			token, _ := jsonparser.GetString(data, "token")
			userToken = token
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestEmptyClaims(t *testing.T) {

	var jwtClaims map[string]interface{}

	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			if userId == "test" && password == "test" {
				return "Administrator", true
			}

			return userId, false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			jwtClaims = ExtractClaims(c)
			c.String(code, message)
		},
	}

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	assert.Empty(t, jwtClaims)
}

func TestUnauthorized(t *testing.T) {
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
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}
