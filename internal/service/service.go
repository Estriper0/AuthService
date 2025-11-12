package service

import "context"

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type IAuthService interface {
	Login(
		ctx context.Context,
		email string,
		password string,
	) (*Tokens, error)

	Register(
		ctx context.Context,
		email string,
		password string,
	) (string, error)

	IsAdmin(
		ctx context.Context,
		uuid string,
	) (bool, error)

	Logout(
		ctx context.Context,
		refreshToken string,
	) error

	Refresh(
		ctx context.Context,
		refreshToken string,
	) (*Tokens, error)
}
