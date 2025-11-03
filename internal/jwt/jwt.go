package jwt

import (
	"time"

	"github.com/Estriper0/auth_service/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

func NewToken(user models.User, app models.App, duration time.Duration) string {
	claims := jwt.MapClaims{}

	claims["user_id"] = user.UUID
	claims["app_id"] = app.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(app.Secret))

	return tokenString
}
