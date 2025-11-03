package jwt

import (
	"time"

	"github.com/Estriper0/auth_service/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func NewAccessToken(user models.User, secret string, duration time.Duration) string {
	claims := jwt.MapClaims{}

	claims["user_id"] = user.UUID
	claims["exp"] = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secret))

	return tokenString
}

func NewRefreshToken(user models.User, secret string, duration time.Duration) string {
	claims := jwt.MapClaims{}

	claims["user_id"] = user.UUID
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["jti"] = uuid.New().String()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secret))

	return tokenString
}
