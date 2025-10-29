package app

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Estriper0/auth_service/internal/models"
	"github.com/Estriper0/auth_service/internal/repository"
)

type AppRepository struct {
	db *sql.DB
}

func New(db *sql.DB) *AppRepository {
	return &AppRepository{
		db: db,
	}
}

func (r *AppRepository) GetByID(
	ctx context.Context,
	id int32,
) (models.App, error) {
	query := "SELECT * FROM apps WHERE id = $1"
	var app models.App
	err := r.db.QueryRowContext(ctx, query, id).Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, repository.ErrAppNotFound
		}
		return models.App{}, err
	}
	return app, nil
}
