package service

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user exists")
	ErrInternal           = errors.New("internal error")
	ErrRefreshBlacklist   = errors.New("error in adding refresh token in blacklist")
	ErrInvalidToken       = errors.New("invalid refresh token")
)
