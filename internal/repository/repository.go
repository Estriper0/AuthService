package repository

import (
	"context"

	"github.com/Estriper0/auth_service/internal/models"
)

type IUserRepository interface {
	GetByEmail(
		ctx context.Context,
		email string,
	) (*models.User, error)

	Create(
		ctx context.Context,
		email string,
		passHash string,
		is_admin bool,
	) (string, error)

	IsAdmin(
		ctx context.Context,
		uuid string,
	) (bool, error)
}
