package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func NewAccessToken(user_id string, isAdmin bool, secret string, duration time.Duration) string {
	claims := jwt.MapClaims{}

	claims["user_id"] = user_id
	claims["is_admin"] = isAdmin
	claims["exp"] = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secret))

	return tokenString
}

func NewRefreshToken(user_id string, isAdmin bool, secret string, duration time.Duration) string {
	claims := jwt.MapClaims{}

	claims["user_id"] = user_id
	claims["is_admin"] = isAdmin
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["jti"] = uuid.New().String()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secret))

	return tokenString
}

func ValidRefreshToken(refreshToken string, secret string) (string, bool, bool) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", false, false
	}

	if !token.Valid {
		return "", false, false
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	user_id, _ := claims["user_id"].(string)
	is_admin, _ := claims["is_admin"].(bool)

	return user_id, is_admin, true
}
