package service

import "context"

type IAuthService interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appId int32,
	) (string, error)

	Register(
		ctx context.Context,
		email string,
		password string,
	) (string, error)

	IsAdmin(
		ctx context.Context,
		uuid string,
	) (bool, error)
}