# JWT Middleware for Gin Framework

[![Build Status](https://travis-ci.org/appleboy/gin-jwt.svg?branch=master)](https://travis-ci.org/appleboy/gin-jwt) [![Go Report Card](https://goreportcard.com/badge/github.com/appleboy/gin-jwt)](https://goreportcard.com/report/github.com/appleboy/gin-jwt) [![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/appleboy/gin-jwt/master/LICENSE)

This is a middleware for [Gin](https://github.com/gin-gonic/gin).

It uses [jwt-go](https://github.com/dgrijalva/jwt-go) to provide a jwt authentication middleware. It provides additional handler functions to provide the `login` api that will generate the token and an additional `refresh` handler that can be used to refresh tokens.

## Install

```bash
$ go get -u https://github.com/appleboy/gin-jwt
```

## Example

Please see server example file.
