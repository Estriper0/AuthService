package tests

import (
	"context"

	"github.com/Estriper0/auth_service/internal/models"
	"github.com/Estriper0/auth_service/internal/repository"
	"github.com/Estriper0/auth_service/internal/repository/app"
)

func (s *TestSuite) TestAppRepository_GetByID_Success() {
	ctx := context.Background()
	repo := app.New(s.db)

	var testApp models.App
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO apps (id, name, secret) VALUES (1, 'test-app', 'secret-123') 
		RETURNING id, name, secret
	`).Scan(&testApp.ID, &testApp.Name, &testApp.Secret)
	s.Require().NoError(err)

	got, err := repo.GetByID(ctx, testApp.ID)
	s.Require().NoError(err)
	s.Equal(testApp.ID, got.ID)
	s.Equal(testApp.Name, got.Name)
	s.Equal(testApp.Secret, got.Secret)
}

func (s *TestSuite) TestAppRepository_GetByID_NotFound() {
	ctx := context.Background()
	repo := app.New(s.db)

	_, err := repo.GetByID(ctx, 999999)
	s.ErrorIs(err, repository.ErrAppNotFound)
}
