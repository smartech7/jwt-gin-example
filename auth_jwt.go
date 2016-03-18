// Package jwt provides Json-Web-Token authentication for the gin framework
// fork from https://github.com/StephanDollberg/go-json-rest-middleware-jwt
package JWT_MIDDLEWARE

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
	"time"
)

// JWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userId is made available as
// request.Env["userID"].(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX#!/usr/bin/env
type JWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required.
	Key []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// Callback function that should perform the authentication of the user based on userId and
	// password. Must return true on success, false on failure. Required.
	Authenticator func(userId string, password string) bool

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(userId string, c *gin.Context) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via request.Env["JWT_PAYLOAD"].
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(userId string) map[string]interface{}
}

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func (mw *JWTMiddleware) MiddlewareInit() {
	if mw.Realm == "" {
		log.Fatal("Realm is required")
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Key == nil {
		log.Fatal("Key required")
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.Authenticator == nil {
		log.Fatal("Authenticator is required")
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(userId string, c *gin.Context) bool {
			return true
		}
	}
}

// MiddlewareFunc makes JWTMiddleware implement the Middleware interface.
func (mw *JWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	mw.MiddlewareInit()

	return func(c *gin.Context) {
		mw.middlewareImpl(c)
		return
	}
}

func (mw *JWTMiddleware) middlewareImpl(c *gin.Context) {

	fmt.Println("middlewareImpl")

	token, err := mw.parseToken(c)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	id := token.Claims["id"].(string)

	if !mw.Authorizator(id, c) {
		mw.unauthorized(c, http.StatusForbidden, "You don't have permission to access.")
		return
	}

	c.Set("JWT_PAYLOAD", token.Claims)
	c.Set("userID", id)
	c.Next()
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) LoginHandler(c *gin.Context) {

	// Initial middleware default setting.
	mw.MiddlewareInit()

	var loginVals Login

	if c.BindJSON(&loginVals) != nil {
		mw.unauthorized(c, http.StatusBadRequest, "Missing usename or password")
		return
	}

	if !mw.Authenticator(loginVals.Username, loginVals.Password) {
		mw.unauthorized(c, http.StatusUnauthorized, "Incorrect Username / Password")
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(loginVals.Username) {
			token.Claims[key] = value
		}
	}

	expire := time.Now().Add(mw.Timeout)
	token.Claims["id"] = loginVals.Username
	token.Claims["exp"] = expire.Unix()
	tokenString, err := token.SignedString(mw.Key)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the JWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) RefreshHandler(c *gin.Context) {
	token, err := mw.parseToken(c)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))

	for key := range token.Claims {
		newToken.Claims[key] = token.Claims[key]
	}

	expire := time.Now().Add(mw.Timeout)
	newToken.Claims["id"] = token.Claims["id"]
	newToken.Claims["exp"] = expire.Unix()
	tokenString, err := newToken.SignedString(mw.Key)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, "Create JWT Token faild")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}

// Helper function to extract the JWT claims
func ExtractClaims(c *gin.Context) map[string]interface{} {

	if _, exists := c.Get("JWT_PAYLOAD"); !exists {
		empty_claims := make(map[string]interface{})
		return empty_claims
	}

	jwt_claims, _ := c.Get("JWT_PAYLOAD")

	return jwt_claims.(map[string]interface{})
}

// Handler that clients can use to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) TokenGenerator(c *gin.Context, userID string) string {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(userID) {
			token.Claims[key] = value
		}
	}

	token.Claims["id"] = userID
	token.Claims["exp"] = time.Now().Add(mw.Timeout).Unix()

	tokenString, err := token.SignedString(mw.Key)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, "Create JWT Token faild")
		return "null"
	}

	return tokenString
}

func (mw *JWTMiddleware) parseToken(c *gin.Context) (*jwt.Token, error) {
	authHeader := c.Request.Header.Get("Authorization")

	if authHeader == "" {
		return nil, errors.New("Auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("Invalid auth header")
	}

	return jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != token.Method {
			return nil, errors.New("Invalid signing algorithm")
		}

		return mw.Key, nil
	})
}

func (mw *JWTMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Realm)

	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
	c.Abort()

	return
}
