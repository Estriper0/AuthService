package service

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAppNotFound        = errors.New("app not found")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user exists")
	ErrInternal           = errors.New("internal error")
)
