package tests

import (
	"context"

	"github.com/Estriper0/auth_service/internal/repository"
	"github.com/Estriper0/auth_service/internal/repository/user"
)

func (s *TestSuite) TestUserRepository_Create_Success() {
	ctx := context.Background()
	repo := user.New(s.db)

	email := "test@example.com"
	passHash := "hashed_password_123"

	uuid, err := repo.Create(ctx, email, passHash)
	s.Require().NoError(err)
	s.NotEmpty(uuid)

	user, err := repo.GetByEmail(ctx, email)

	s.Require().NoError(err)
	s.Equal(email, user.Email)
	s.Equal(passHash, user.PassHash)
}

func (s *TestSuite) TestUserRepository_Create_DuplicateEmail() {
	ctx := context.Background()
	repo := user.New(s.db)

	email := "duplicate@example.com"
	passHash := "hash123"

	_, err := repo.Create(ctx, email, passHash)
	s.Require().NoError(err)

	_, err = repo.Create(ctx, email, "another_hash")
	s.ErrorIs(err, repository.ErrUserExists)
}

func (s *TestSuite) TestUserRepository_GetByEmail_Success() {
	ctx := context.Background()
	repo := user.New(s.db)

	email := "getbyemail@example.com"
	passHash := "securehash"

	uuid, err := repo.Create(ctx, email, passHash)
	s.Require().NoError(err)

	user, err := repo.GetByEmail(ctx, email)
	s.Require().NoError(err)
	s.Equal(uuid, user.UUID)
	s.Equal(email, user.Email)
	s.Equal(passHash, user.PassHash)
}

func (s *TestSuite) TestUserRepository_GetByEmail_NotFound() {
	ctx := context.Background()
	repo := user.New(s.db)

	_, err := repo.GetByEmail(ctx, "nonexistent@example.com")
	s.ErrorIs(err, repository.ErrUserNotFound)
}

func (s *TestSuite) TestUserRepository_IsAdmin_AdminUser() {
	ctx := context.Background()
	repo := user.New(s.db)

	var uuid string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (email, pass_hash, is_admin) 
		VALUES ('admin@example.com', 'hash', true) 
		RETURNING uuid
	`).Scan(&uuid)
	s.Require().NoError(err)

	isAdmin, err := repo.IsAdmin(ctx, uuid)
	s.Require().NoError(err)
	s.True(isAdmin)
}

func (s *TestSuite) TestUserRepository_IsAdmin_NonAdminUser() {
	ctx := context.Background()
	repo := user.New(s.db)

	uuid, err := repo.Create(ctx, "user@example.com", "hash")
	s.Require().NoError(err)

	isAdmin, err := repo.IsAdmin(ctx, uuid)
	s.Require().NoError(err)
	s.False(isAdmin)
}

func (s *TestSuite) TestUserRepository_IsAdmin_NotFound() {
	ctx := context.Background()
	repo := user.New(s.db)

	isAdmin, err := repo.IsAdmin(ctx, "00000000-0000-0000-0000-000000000000")
	s.False(isAdmin)
	s.ErrorIs(err, repository.ErrUserNotFound)
}
