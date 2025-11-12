package user

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Estriper0/auth_service/internal/models"
	"github.com/Estriper0/auth_service/internal/repository"
	"github.com/lib/pq"
)

type UserRepository struct {
	db *sql.DB
}

func New(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (r *UserRepository) Create(
	ctx context.Context,
	email string,
	passHash string,
	is_admin bool,
) (string, error) {
	query := "INSERT INTO users (email, pass_hash, is_admin) VALUES ($1, $2, $3) RETURNING uuid"

	var user_uuid string
	err := r.db.QueryRowContext(ctx, query, email, passHash, is_admin).Scan(&user_uuid)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return "", repository.ErrUserExists
		}
		return "", err
	}
	return user_uuid, nil
}

func (r *UserRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*models.User, error) {
	query := "SELECT uuid, email, pass_hash, is_admin FROM users WHERE email = $1"

	var user models.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(&user.UUID, &user.Email, &user.PassHash, &user.IsAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) IsAdmin(
	ctx context.Context,
	uuid string,
) (bool, error) {
	query := "SELECT is_admin FROM users WHERE uuid = $1"

	var IsAdmin bool
	err := r.db.QueryRowContext(ctx, query, uuid).Scan(&IsAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, repository.ErrUserNotFound
		}
		return false, err
	}
	return IsAdmin, nil
}
